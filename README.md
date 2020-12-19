# pecat
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fandrewbae%2Fpecat&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23FFFFFF&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)  
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
