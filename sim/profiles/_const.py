"""Shared constants referenced by wheel profile modules.

The factory-state filenames mirror the constants of the same name in
wheel_sim.py. They are duplicated here (not imported) so the profiles package
never imports wheel_sim — wheel_sim imports the registry, and a cycle would
break module load order."""

_FACTORY_STATE_FILE_W17_RGB = "factory_state_w17_rgb.json"
_FACTORY_STATE_FILE_W08_SM = "factory_state_w08_sm.json"
_FACTORY_STATE_FILE_KSPRO = "factory_state_kspro.json"
