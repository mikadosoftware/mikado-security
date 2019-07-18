#! -*- coding:utf-8 -*-

from setuptools import setup, find_packages
import glob

def get_data_files(inrepo_dirlist):
    """Python Packaging is (still) awkward.  I am writing this longform as
    it took a long time to work out and there are no good answers
    online as yet.

    In some cases I want to include non-python files in my wheel /
    distribution.  This might be obvious stuff like License files or
    in workstation cases, config files just to be added to allow
    configuration of the bin script.

    Python distutils/setuptools has concepts of both `data_files` and
    `package_data`.  `package_data` is non-python files stored inside
    the python package (i.e. the parts marked by `__init__.py`
    directories).  The aim is to *distribute* those onto target disk
    inside the pacakge directories again.

    `data_files` are kept outside of pacakge directories, in the repo
    as well as on target disk.  `data_files` should be written to
    target disk at `sys.prefix()`, but it seems that has changed in
    code and is now landing at '/usr/local'.
    
    the data_files parameter in setup expects a list of tuples like::

        ('config/.next/templates', ['config/.next/templates/apt.template'])
 
    Each tuple represents one file to be distributed, globbing is not
    working so well.  the left hand side is the format of directory
    structure to be created on target disk under /usr/local and the
    right hand is the path of the file *in the repo* that will be
    placed on target disk.

    This is correct for `setuptools.__version__ == '39.0.1'`

    So now we build a helper to get and then retireve the data files
    just so I can populate them in the users local dir

    [X] list dirs to search / rebuild
    [ ] recovery - how to find where we put them?? !!

    """
    
    data_files = []
    for folder in inrepo_dirlist:
        for dirpath, dirnames, filenames in os.walk(folder):
            data_files.append((dirpath,
                               [os.path.join(dirpath, f) for f in filenames]))
            
    return data_files

# get version data
with open("VERSION") as fo:
    version = fo.read()

setup(
     name='mikado-security',
     version=version,
     description='A Description to change',
     author='author',
     packages=find_packages(exclude=('tests')),
     # Any scripts (i.e. python/bash) found here will be added to PATH
     scripts=glob.glob('scripts/*'),
#     data_files=get_data_files(['relative/data/file/location',])
)
