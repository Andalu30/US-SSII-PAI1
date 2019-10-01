import hashlib
import os
from crontab import CronTab

def ConfigFile():
    def creaConfigFile():
        os.makedirs("/etc/SSII-PA1/", 0o0755)
        string_config=";Algoritmo\n" \
                     "SHA1\n" \
                     ";Tiempo\n" \
                     "24h\n" \
                     ";Nombre Fichero salida\n" \
                     "SSIIoutput\n" \
                      ";Ficheros\n"
        text_file = open("/etc/SSII-PA1/SSIIPA1.cfg", "w")
        text_file.write(string_config)
        text_file.close()

    def leeConfigFile():
        text_file = open("/etc/SSII-PA1/SSIIPA1.cfg", "r")

        argumentos = []

        for line in text_file:
            li = line.strip()
            if not li.startswith(";"):
                argumentos.append(li)
                line.rstrip()
        archivos = argumentos[3:]

        if os.path.isfile("/etc/SSII-PA1/hashes.cfg"):
            getHashfromFile(argumentos[0], archivos,comprueba=True)
        else:
            getHashfromFile(argumentos[0], archivos)







    if(os.path.isfile("/etc/SSII-PA1/SSIIPA1.cfg")):
        leeConfigFile()
    else:
        creaConfigFile()



def getHashfromFile(tipoHash, archivos,comprueba=False):
    if tipoHash  == "SHA1":
        hashes = []
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo).read().encode("UTF-8"))
            hashes.append(hash.hexdigest())
    else:
        print("Fuck this shit im out")
        # TODO!!!

    if len(hashes)!=len(archivos):
        comprueba=False




    if comprueba == False:
        # Guarda hashes en archivo
        text_file = open("/etc/SSII-PA1/hashes.cfg", "w")
        for hash in hashes:
            text_file.write(hash + "\n")
        text_file.close()
    else:
        compruebaSHAs(tipoHash, archivos)










def compruebaSHAs(tipoHash, archivos):
    file = open("/etc/SSII-PA1/hashes.cfg","r")
    hashesGuardados = []
    for line in file:
        hashesGuardados.append(line.strip("\n"))

    hahesArchivos = []
    if tipoHash  == "SHA1":
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo).read().encode("UTF-8"))
            hahesArchivos.append(hash.hexdigest())


    print(hahesArchivos, hashesGuardados)

    fallos = []
    for i in range(len(hahesArchivos)):
        if hashesGuardados[i] != hahesArchivos[i]:
            fallos.append(i)
        else:
            continue

    if len(fallos)!=0:
        generaIncidentes(fallos)
        generaKPIs(fallos)


def generaIncidentes(fallos):
    print("fallo!!!")
    print(fallos)
    pass

def generaKPIs(fallos):
  pass



#main
ConfigFile()

#
# cron = CronTab(user='root')
# job = cron.new(command='python3 testing.py')
# job.minute.every(1)
# cron.write()

