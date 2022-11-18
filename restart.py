import time
print("Restarting script...")
time.sleep(2)
exec(open("main.py").read())
time.sleep(1)
sys.exit()