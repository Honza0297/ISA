import subprocess
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
NC ='\x1b[0m'
HEADER = '\033[95m'

program = "./dns" 
bad_inputs = [
"sdfadf", # nonsense
"-r -x -6", # no -s and address
"", # nothing
"-s", # only -s without anthing
"-s server -p AHOJ", # port as string
"-s kazi.fit.vutbr.cz www.google.com -x", # reverse when DN typed

]

good_inputs = [
"-s kazi.fit.vutbr.cz www.zive.cz -r",
"-s kazi.fit.vutbr.cz www.zive.cz",
"-s 8.8.8.8 www.fit.vutbr.cz -p 53",
"-s kazi.fit.vutbr.cz 147.229.9.23 -x", # www.fit.vutbr.cz
]
err = False
print(HEADER + "***Bad inputs, error is expected (white - stderr from program)***" + NC)
for bad in range(len(bad_inputs)):
    err = False
    try:
        print(OKBLUE + program + " " +  bad_inputs[bad] + NC)
        cmd =[program] + bad_inputs[bad].split(" ")
        #print(cmd)
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        err = True
        print(OKGREEN + "OK" + NC)
    finally:
        if not err:
            print(FAIL + "ERR with args: " + bad_inputs[bad] + "\n Error was expected"+ NC)

print(HEADER + "***Good inputs, error is not expected (white - stderr from program)***" + NC)
for good in range(len(good_inputs)):
    err = False
    try:
        print(OKBLUE + program +  " " + good_inputs[good]+ NC)
        cmd = [program] + good_inputs[good].split(" ")
        subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        err = True
        print(FAIL + "ERR with args: " + good_inputs[good] + "\nReturn code was "+ str(e.returncode)+ NC)
    finally:
        if not err:
            print(OKGREEN + "OK" + NC)
            