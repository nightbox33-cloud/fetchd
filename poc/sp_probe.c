/* Native stack probe: returns the current frame address (a stable proxy for RSP). */
void *sp_probe(void) { return __builtin_frame_address(0); }
