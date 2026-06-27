"""项目根 conftest.py - pytest 全局配置

解决多 module 同名 test 文件冲突 (e.g. login_analyze 和 credential_analyze 都有 test_matcher.py).
用 --import-mode=importlib 强制每个 test file 独立 import, 避免冲突.
"""
import sys
from pathlib import Path

# 把项目根加进 sys.path
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))