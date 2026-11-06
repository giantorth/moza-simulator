"""Input sources feeding uhub.state.InputMerger.

Each source calls `sink(source_id, SourceState)` on change and
`sink_remove(source_id)` when a device goes away, always on the bridge's
asyncio loop (thread-based sources hop over with call_soon_threadsafe).
"""
