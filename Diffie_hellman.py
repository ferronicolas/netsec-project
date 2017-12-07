import scipy,os

def main():
    a = os.urandom(1024)
    b = os.urandom(2048)

    print scipy.randprime(a,b)

main()