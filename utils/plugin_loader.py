import os
import sys
import json
import importlib.util
import inspect


PLUGIN_DIR = os.path.expanduser("~/.reconnor/plugins")


def load_plugins():
    if not os.path.isdir(PLUGIN_DIR):
        return {}

    plugins = {}
    sys.path.insert(0, PLUGIN_DIR)

    for fname in sorted(os.listdir(PLUGIN_DIR)):
        if fname.endswith(".py") and not fname.startswith("_"):
            mod_name = fname[:-3]
            path = os.path.join(PLUGIN_DIR, fname)
            spec = importlib.util.spec_from_file_location(mod_name, path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for name, obj in inspect.getmembers(mod):
                    if inspect.isclass(obj) and hasattr(obj, "run") and hasattr(obj, "description"):
                        plugins[mod_name] = obj
                        break

    if plugins:
        print(f"[*] Loaded {len(plugins)} plugin(s): {', '.join(plugins.keys())}")
    return plugins


def load_config():
    config_paths = [
        os.path.join(os.getcwd(), "reconnor.json"),
        os.path.join(os.path.expanduser("~/.reconnor"), "config.json"),
        os.path.expanduser("~/.reconnor.json"),
    ]
    for path in config_paths:
        if os.path.exists(path):
            try:
                with open(path) as f:
                    return json.load(f)
            except:
                pass
    return {}
