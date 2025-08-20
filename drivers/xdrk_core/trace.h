#pragma once

//
// WPP Tracing Configuration
// Define trace GUIDs and levels for the XDR core driver
//

#define WPP_CONTROL_GUIDS \
    WPP_DEFINE_CONTROL_GUID( \
        XdrCoreTraceGuid, (12345678,1234,5678,9012,123456789012), \
        WPP_DEFINE_BIT(XDR_TRACE_DRIVER)      \
        WPP_DEFINE_BIT(XDR_TRACE_DEVICE)      \
        WPP_DEFINE_BIT(XDR_TRACE_RING)        \
        WPP_DEFINE_BIT(XDR_TRACE_CALLBACKS)   \
        WPP_DEFINE_BIT(XDR_TRACE_EVENTS)      \
        WPP_DEFINE_BIT(XDR_TRACE_CONFIG)      \
        WPP_DEFINE_BIT(XDR_TRACE_ERRORS)      \
    )

// Trace levels
#define TRACE_LEVEL_NONE        0
#define TRACE_LEVEL_CRITICAL    1
#define TRACE_LEVEL_ERROR       2
#define TRACE_LEVEL_WARNING     3
#define TRACE_LEVEL_INFORMATION 4
#define TRACE_LEVEL_VERBOSE     5

// Trace macros
#define TraceEvents(Level, Flags, Msg, ...) \
    WPP_LEVEL_FLAGS_LOGGER(XdrCoreTraceGuid, Level, Flags)(Msg, ##__VA_ARGS__)

// Specific trace macros for different components
#define TraceDriver(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_DRIVER, Msg, ##__VA_ARGS__)

#define TraceDevice(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_DEVICE, Msg, ##__VA_ARGS__)

#define TraceRing(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_RING, Msg, ##__VA_ARGS__)

#define TraceCallbacks(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_CALLBACKS, Msg, ##__VA_ARGS__)

#define TraceEventGeneration(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_EVENTS, Msg, ##__VA_ARGS__)

#define TraceConfig(Level, Msg, ...) \
    TraceEvents(Level, XDR_TRACE_CONFIG, Msg, ##__VA_ARGS__)

#define TraceError(Msg, ...) \
    TraceEvents(TRACE_LEVEL_ERROR, XDR_TRACE_ERRORS, Msg, ##__VA_ARGS__)

#define TraceWarning(Msg, ...) \
    TraceEvents(TRACE_LEVEL_WARNING, XDR_TRACE_ERRORS, Msg, ##__VA_ARGS__)

#define TraceInfo(Msg, ...) \
    TraceEvents(TRACE_LEVEL_INFORMATION, XDR_TRACE_DRIVER, Msg, ##__VA_ARGS__)

// Entry/exit tracing
#define FuncEntry() \
    TraceEvents(TRACE_LEVEL_VERBOSE, XDR_TRACE_DRIVER, "Entering %!FUNC!")

#define FuncExit() \
    TraceEvents(TRACE_LEVEL_VERBOSE, XDR_TRACE_DRIVER, "Exiting %!FUNC!")

#define FuncExitWithStatus(Status) \
    TraceEvents(TRACE_LEVEL_VERBOSE, XDR_TRACE_DRIVER, "Exiting %!FUNC! with status %!STATUS!", Status)

// Error tracking
#define LogError(Status, Msg, ...) \
    TraceEvents(TRACE_LEVEL_ERROR, XDR_TRACE_ERRORS, "%!FUNC! failed: " Msg " (Status: %!STATUS!)", ##__VA_ARGS__, Status)

// Performance tracking
#define TracePerfStart(Name) \
    LARGE_INTEGER Name##_Start; \
    KeQuerySystemTimePrecise(&Name##_Start)

#define TracePerfEnd(Name, Operation) \
    do { \
        LARGE_INTEGER Name##_End; \
        KeQuerySystemTimePrecise(&Name##_End); \
        LONGLONG Duration = Name##_End.QuadPart - Name##_Start.QuadPart; \
        TraceEvents(TRACE_LEVEL_INFORMATION, XDR_TRACE_RING, \
                   "Performance: " Operation " took %lld 100ns units", Duration); \
    } while (0)

// Ring buffer tracing
#define TraceRingBufferStats(DeviceContext) \
    do { \
        PXDR_RING_BUFFER Ring = &(DeviceContext)->RingBuffer; \
        TraceRing(TRACE_LEVEL_INFORMATION, \
                 "Ring buffer stats: WriteIndex=%lld, ReadIndex=%lld, Size=%zu", \
                 Ring->WriteIndex, Ring->ReadIndex, Ring->Size); \
    } while (0)

// Configuration change tracing
#define TraceConfigChange(Field, OldValue, NewValue) \
    TraceConfig(TRACE_LEVEL_INFORMATION, \
               "Config change: " #Field " changed from %lu to %lu", \
               (ULONG)(OldValue), (ULONG)(NewValue))

#ifdef WPP_TRACING
// Include the auto-generated header for WPP
#include "xdrk_core.tmh"
#endif