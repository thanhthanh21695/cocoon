#!/usr/bin/env python3

import sys
from translate import translate_with_roles, translate_harmony_manual, translate_harmony_library, translate_hunyuan


def main():
    try:
        if sys.stdin.isatty():
            print('Paste text (Ctrl+D when done):', file=sys.stderr)

        text = sys.stdin.read().strip()
        if not text:
            sys.exit("No text provided.")

        target_lang = sys.argv[1] if len(sys.argv) > 1 else "German (de)"
        method = "harmony"

        if len(sys.argv) > 2:
            flag = sys.argv[2]
            if flag == "--harmony":
                method = "harmony"
            elif flag == "--harmony-lib":
                method = "harmony-lib"
            elif flag == "--roles":
                method = "roles"
            elif flag == "--hunyuan":
                method = "hunyuan"

        print(f"Translating to {target_lang}... (method: {method})", file=sys.stderr)

        model = "google/gemma-3-12b-it" if method != "hunyuan" else "hunyuan"

        if method == "roles":
            result = translate_with_roles(text, target_lang, model=model, verbose=True)
        elif method == "harmony-lib":
            result = translate_harmony_library(text, target_lang, model=model, verbose=True)
        elif method == "hunyuan":
            result = translate_hunyuan(text, target_lang, model=model, verbose=True)
        else:
            result = translate_harmony_manual(text, target_lang, model=model, verbose=True)

        print(result)

    except KeyboardInterrupt:
        sys.exit("\nCancelled.")
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
