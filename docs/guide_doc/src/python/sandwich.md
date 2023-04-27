# Sandwich

## Description

`Sandwich` is a class responsible for doing the glue with library code.

At `__init__`, it automatically searches and loads the Sandwich library.
After a successful initialization, `Sandwich()` class translate function calls from Python to native library calls.

Function symbols are lazily-resolved.

Input:
- `library.Path` (optional)

Return:
- `Sandwich` handle

## Usage

```python
from sandwich import Sandwich

sw = Sandwich()
```
