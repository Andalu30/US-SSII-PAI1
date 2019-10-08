import hashlib
import os
from crontab import CronTab
from time import sleep
from daemonize import Daemonize


tiempoEsperaDemonio = 0


def ConfigFile():
    def creaConfigFile():
        print("Creando archivo de configuración. Defina los archivos que hay que comprobar.")
        os.makedirs("/etc/SSII-PAI1/", 0o0755)
        string_config=";Algoritmo\n" \
                     "SHA1\n" \
                     ";Tiempo\n" \
                     "24h\n" \
                     ";Nombre Fichero salida\n" \
                     "SSIIoutput\n" \
                      ";Ficheros\n"
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "w")
        text_file.write(string_config)
        text_file.close()

    def leeConfigFile():

        def cantidadHashesGuardos():
            text_file = open("/etc/SSII-PAI1/hashes.cfg", "r")
            return len(text_file.readlines())



        print("Cargando archivo de configuración")
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "r")

        argumentos = []
        for line in text_file:
            li = line.strip()
            if not li.startswith(";"):
                argumentos.append(li)
                line.rstrip()
        archivos = argumentos[3:]

        print(argumentos[1])
        tiempoEsperaDemonio = configuraDemonio(argumentos[1])



        if os.path.isfile("/etc/SSII-PAI1/hashes.cfg"):
            if (len(archivos) == cantidadHashesGuardos()):
                getHashfromFile(argumentos[0], archivos,comprueba=True)
            else:
                getHashfromFile(argumentos[0], archivos)
        else:
            getHashfromFile(argumentos[0], archivos)








    


    if(os.path.isfile("/etc/SSII-PAI1/SSIIPAI1.cfg")):
        leeConfigFile()
    else:
        creaConfigFile()





def getHashfromFile(tipoHash, archivos,comprueba=False):
    if tipoHash  == "SHA1":
        hashes = []
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo).read().encode('utf-8'))
            hashes.append(hash.hexdigest())
            print(hashes)
    else:
        print("Fuck this shit im out")
        # TODO!!!



    if comprueba == False:
        print("Guardando nuevos hashes en el archivo de cofiguración")
        text_file = open("/etc/SSII-PAI1/hashes.cfg", "w")
        for hash in hashes:
            text_file.write(hash + "\n")
        text_file.close()
    else:
        compruebaSHAs(tipoHash, archivos)










def compruebaSHAs(tipoHash, archivos):
    file = open("/etc/SSII-PAI1/hashes.cfg","r")
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
        generaIncidentes(fallos, archivos)
        generaKPIs(fallos, archivos)
    else:
        todoBien()


def todoBien():
    print("Todo bien de momento :)")

def generaIncidentes(fallos,archivos):
    for fallo in fallos:
        print("El archivo {} ha fallado".format(archivos[fallo]))

def generaKPIs(fallos,archivos):
  pass





def configuraDemonio(tiempoString):
    if tiempoString.endswith("h"):
        tiempo = 3600*tiempoString[:-1]
    elif tiempoString.endswith("m"):
        tiempo = 60*tiempoString[:-1]
    elif tiempoString.endswith("s"):
        tiempo = tiempoString[:-1]
    elif tiempoString.endswith("d"):
        tiempo = 3600*24*tiempoString[:-1]
        print(tiempo)
    return tiempo



def bucleDemonio():
    ConfigFile()
    print(tiempoEsperaDemonio)
    sleep(tiempoEsperaDemonio)


pid = "/tmp/test.pid"
daemon = Daemonize(app="PAI1", pid=pid, action=bucleDemonio())
daemon.start()


