## Static Binary Analysis Setup

Our implementation of the static binary analysis tool is based on [angr](https://angr.io/).
Specifically, we developed our patched version of angr.

1. Setup python virtual environment (recommended)

It is highly recommended to use a python virtual environment to install and use angr.
To set up the virtual environment, you can either choose to use `virtualenvwrapper` or `conda`.
In our own experiments, we used [miniconda](https://docs.conda.io/en/latest/miniconda.html) to set up the virtual environment.

``` bash
# 
# 1. (Optional) Install virtualenvwrapper
#
python3.8 -m pip install virtualenvwrapper
echo export WORKON_HOME=$HOME/.virtualenvs >> ~/.bashrc
(optional) echo export VIRTUALENVWRAPPER_PYTHON=/usr/bin/python3.8 >> ~/.bashrc
echo source /usr/local/bin/virtualenvwrapper.sh >> ~/.bashrc
(if virtualenvwrapper.sh cannot be found under /usr/local/bin: try echo source ~/.local/bin/virtualenvwrapper.sh >> ~/.bashrc)
source ~/.bashrc
# create venv
mkvirtualenv palantir-env -p python3.8
workon palantir-env
# 
# 2. (Optional) Install conda
#
export CONDA_PREFIX=/usr/local/miniconda3
wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh -O install_conda.sh
chmod +X install_conda.sh
sudo bash install_conda.sh -p $CONDA_PREFIX -b
rm install_conda.sh
# create conda venv
conda create -n palantir-env python=3.8
conda activate palantir-env
```

2. Setup angr

We patched and developed our angr at [angr-dev](../angr-dev/).
We also uploaded relevant requirements of our patched-angr at `static-analysis/dependencies/angr_version_ref.txt` for referencing the versions only.

All you actually need to do is to install those dependent packages manually.

``` bash
# download this repo first
(palantir-env) cd /path/to/angr-dev
(palantir-env) pip install -e archinfo
(palantir-env) pip install -e pyvex
(palantir-env) pip install -e claripy
(palantir-env) pip install -e ailment 
(palantir-env) pip install -e cle 
(palantir-env) pip install -e angr
```

3. Setup dependencies for other miscellaneous tools

We provided a set of miscellaneous tools both for auxiliary and analysis.
To set up the environment, you should install requirements under `static-analysis/dependencies/requirements.txt`.

```
(palantir-env) pip install -r static-analysis/dependencies/requirements.txt
```

4. Setup redis server

Before starting the static binary analysis, you should set up the [redis](https://redis.io/) database server for dumping the taint summarization results.
Also, please install the [redis-dump](https://github.com/delano/redis-dump) tool to back up the redis data into a JSON file.

``` bash
# install redis server
$ apt-get install redis
# install redis-dump
$ apt-get install ruby ruby-dev gcc
$ gem install redis-dump
```