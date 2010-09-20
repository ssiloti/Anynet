from shutil import rmtree
from os import mkdir
from os import remove

for i in range(10):
    rmtree("./" + str(i) + "/non_authoritative")
    remove("./" + str(i) + "/traffic.db")
    remove("./" + str(i) + "/indirect_credits")
    mkdir("./" + str(i) + "/non_authoritative")
