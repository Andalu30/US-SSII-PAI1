import hashlib
import os
import logging
from time import sleep
from daemonize import Daemonize


logFilename = "test.log"


logging.basicConfig(filename=logFilename,level=logging.DEBUG,format='%(asctime)s:%(levelname)s:%(message)s')


tiempoEsperaDemonio = 0


def ConfigFile():
    def creaConfigFile():
        logging.debug("Creando archivo de configuración. Defina los archivos que hay que comprobar.")
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



        logging.debug("Cargando archivo de configuración")
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "r")

        argumentos = []
        for line in text_file:
            li = line.strip()
            if not li.startswith(";"):
                argumentos.append(li)
                line.rstrip()
        archivos = argumentos[3:]

        logging.debug(argumentos[1])
        tiempoEsperaDemonio = configuraDemonio(argumentos[1])



        if os.path.isfile("/etc/SSII-PAI1/hashes.cfg"):
            if (len(archivos) == cantidadHashesGuardos()):
                getHashfromFile(argumentos[0], archivos,comprueba=True)
            else:
                getHashfromFile(argumentos[0], archivos)
        else:
            getHashfromFile(argumentos[0], archivos)




    if(os.path.isfile("/etc/SSII-PAI1/SSIIPAI1.cfg")):
        # Si existe el archivo de configuracion leerlo y continuar, sino, crearlo
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
    elif tipoHash == "MD5":
            hashes = []
            for archivo in archivos:
                hash = hashlib.md5(open(archivo).read().encode('utf-8'))
                hashes.append(hash.hexdigest())
                print(hashes)
    elif tipoHash == "SHA256":
            hashes = []
            for archivo in archivos:
                hash = hashlib.sha256(open(archivo).read().encode('utf-8'))
                hashes.append(hash.hexdigest())
                print(hashes)
    elif tipoHash == "SHA512":
        hashes = []
        for archivo in archivos:
            hash = hashlib.sha512(open(archivo).read().encode('utf-8'))
            hashes.append(hash.hexdigest())
            print(hashes)


    if comprueba == False:
        logging.debug("Guardando nuevos hashes en el archivo de cofiguración")
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
    if tipoHash == "SHA1":
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo).read().encode("UTF-8"))
            hahesArchivos.append(hash.hexdigest())
    elif tipoHash == "MD5":
        for archivo in archivos:
            hash = hashlib.md5(open(archivo).read().encode("UTF-8"))
            hahesArchivos.append(hash.hexdigest())
    elif tipoHash == "SHA256":
        for archivo in archivos:
            hash = hashlib.sha256(open(archivo).read().encode("UTF-8"))
            hahesArchivos.append(hash.hexdigest())
    elif tipoHash == "SHA512":
        for archivo in archivos:
            hash = hashlib.sha512(open(archivo).read().encode("UTF-8"))
            hahesArchivos.append(hash.hexdigest())

    logging.debug(hahesArchivos, hashesGuardados)

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
    logging.debug("Todo bien de momento :)")

def generaIncidentes(fallos,archivos):
    for fallo in fallos:
        logging.warning("El archivo {} ha fallado".format(archivos[fallo]))

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
        logging.debug("Tiempo: {}".format(tiempo))
    return tiempo



def bucleDemonio():
    ConfigFile()
    logging.log(tiempoEsperaDemonio)
    sleep(tiempoEsperaDemonio)



logging.debug("Hello World")


# pid = "/tmp/test.pid"
# daemon = Daemonize(app="PAI1", pid=pid, action=bucleDemonio())
# daemon.start()


