import sys
import warnings


_orig_showwarning = warnings.showwarning


def _filtered_showwarning(message, category, filename, lineno, file=None, line=None):
    try:
        text = str(message)
    except Exception:
        text = ""
    if "Pydantic serializer warnings" in text:
        return
    return _orig_showwarning(message, category, filename, lineno, file=file, line=line)


def _running_tests(argv):
    for arg in argv:
        if not arg:
            continue
        if "unittest" in arg or "pytest" in arg:
            return True
        if "tests" in arg:
            return True
    return False


if _running_tests(sys.argv):
    warnings.showwarning = _filtered_showwarning
    warnings.filterwarnings(
        "ignore",
        message=r"^Pydantic serializer warnings:[\s\S]*",
        category=UserWarning,
    )
