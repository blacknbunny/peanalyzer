# peanalyzer
Advanced Portable Executable File Analyzer

**_Python 3.5.2 : Tested (Working)_**

## Usage
  python peanalyzer.py --file file.exe --show all|file-path|general|dos-header|file-header|optional-header|data-directory|section-headers|imports
  
  python peanalyzer.py --file file.exe --disassemble all
  
## Installation
  ```
  git clone https://github.com/blacknbunny/peanalyzer.git && cd peanalyzer/
  pip install pefile
  pip install capstone
  ```
 
## Asciinema
  https://asciinema.org/a/5yBJgGZaFdOXNvsoE0SR8LIRC

## General
  ![](https://i.imgur.com/J0Xct4R.png)
## Dos Header
  ![](https://i.imgur.com/EKMAtnL.png)
## File Header
  ![](https://i.imgur.com/4BlKQ8w.png)
## Optional Header
  ![](https://i.imgur.com/1J2L0OW.png)
## Data Directory
  ![](https://i.imgur.com/WrnN2dU.png)
## Section Headers
  ![](https://i.imgur.com/6w8WYYa.png)
## Imports (Dll, Function Adress, Function)
  ![](https://i.imgur.com/ekOVXM8.png)
