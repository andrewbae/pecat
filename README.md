# pecat

An open-source multi-platform Windows Portable Executable(PE) analyzing module.

```python
import pecat
pe = pecat.PE("./sample.exe")
pe.show_info()
```

pecat is in the development stage yet.

## Installation

pecat is based on python3. You can install pecat as easily with using `pip3`.

```
python3 -m pip install --upgrade pip
python3 -m pip install --user --upgrade hexdump pecat
```