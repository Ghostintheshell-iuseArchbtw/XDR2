//! Event Processing Pipeline
//! 
//! Coordinates event flow from driver to storage and rules engine.

use crate::driver::{SharedDriver, XdrDriver};
use crate::events::{EventEnvelope, EventProcessor};
use crate::rules::RulesEngine;
use crate::storage::EventStorage;
use crate::{LibResult, XdrError};
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

/// Event processing pipeline
pub struct EventPipeline {
    driver: SharedDriver,
    processor: EventProcessor,
    storage: Arc<EventStorage>,
    rules_engine: Arc<RulesEngine>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl EventPipeline {
    pub fn new(
        driver: SharedDriver,
        storage: Arc<EventStorage>,
        rules_engine: Arc<RulesEngine>,
    ) -> Self {
        Self {
            driver,
            processor: EventProcessor::new(),
            storage,
            rules_engine,
            shutdown_tx: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx = Some(shutdown_tx);

        info!("Starting event processing pipeline");

        // Main processing loop
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Pipeline shutdown requested");
                    break;
                }
                _ = self.process_events() => {
                    // Continue processing
                }
            }
        }

        Ok(())
    }

    async fn process_events(&self) -> Result<()> {
        let mut driver = self.driver.lock().unwrap();
        
        if !driver.is_mapped() {
            warn!("Shared memory not mapped, attempting to map");
            if let Err(e) = driver.map_shared_memory() {
                error!("Failed to map shared memory: {}", e);
                sleep(Duration::from_secs(5)).await;
                return Ok(());
            }
        }

        let ring = driver.shared_memory()?;
        
        // Wait for events with timeout
        if !ring.wait_for_events(1000)? {
            return Ok(()); // Timeout, continue loop
        }

        let mut events_processed = 0;
        let mut batch = Vec::new();

        // Process available events in batches
        while let Some(raw_event) = ring.read_event()? {
            match self.processor.process_event(&raw_event) {
                Ok(event) => {
                    // Apply rules
                    if let Ok(alerts) = self.rules_engine.evaluate_event(&event) {
                        if !alerts.is_empty() {
                            info!("Rule alerts for event {}: {:?}", event.id, alerts);
                        }
                    }

                    batch.push(event);
                    events_processed += 1;

                    // Process batch when it reaches size limit
                    if batch.len() >= 100 {
                        if let Err(e) = self.storage.store_events_batch(&batch) {
                            error!("Failed to store event batch: {}", e);
                        }
                        batch.clear();
                    }
                }
                Err(e) => {
                    error!("Failed to process event: {}", e);
                }
            }
        }

        // Store remaining events
        if !batch.is_empty() {
            if let Err(e) = self.storage.store_events_batch(&batch) {
                error!("Failed to store final batch: {}", e);
            }
        }

        if events_processed > 0 {
            debug!("Processed {} events", events_processed);
        }

        Ok(())
    }

    pub async fn shutdown(&mut self) -> Result<()> {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(()).await;
        }
        Ok(())
    }
}