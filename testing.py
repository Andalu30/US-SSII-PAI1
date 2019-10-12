import hashlib
import os
import logging
from cryptography.fernet import Fernet
from time import sleep
from daemonize import Daemonize


logFilename = "PAI1.log"
logging.basicConfig(filename=logFilename,level=logging.DEBUG,format='%(asctime)s:%(levelname)s:%(message)s')

key = Fernet.generate_key()
logging.debug(key) #TODO: quitar esto para seguridad
fernet = Fernet(key)


tiempoEsperaDemonio = 30



def ConfigFile():
    def creaConfigFile():
        logging.debug("Creando archivo de configuración. Defina los archivos que hay que comprobar.")
        os.makedirs("/etc/SSII-PAI1/", 0o0755)
        string_config=";Algoritmo\n" \
                     "SHA1\n" \
                     ";Tiempo\n" \
                     "1m\n" \
                     ";Nombre Fichero salida\n" \
                     "SSIIoutput\n" \
                      ";Ficheros\n"
        text_file = open("/etc/SSII-PAI1/SSIIPAI1.cfg", "w")
        text_file.write(string_config)
        text_file.close()
        tiempoEsperaDemonio=60

    def leeConfigFile():

        def cantidadHashesGuardos():

            file = open("/etc/SSII-PAI1/hashes.cfg", "rb")
            encrypted = file.read()
            file.close()
            decrypted = fernet.decrypt(encrypted)
            logging.debug(decrypted.decode('utf-8'))
            logging.debug("CantidadHashesGuardados: {}".format(len(decrypted.decode("utf-8").split('\n'))))
            logging.debug(decrypted.decode("utf-8").split('\n'))
            return len(decrypted.decode("utf-8").split('\n'))

            # text_file = open("/etc/SSII-PAI1/hashes.cfg", "r")
            # return len(text_file.readlines())



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
    hashes = []

    if tipoHash  == "SHA1":
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo,'rb').read())
            hashes.append(hash.hexdigest())
    elif tipoHash == "MD5":
        for archivo in archivos:
            hash = hashlib.md5(open(archivo,'rb').read())
            hashes.append(hash.hexdigest())
    elif tipoHash == "SHA256":
        for archivo in archivos:
            hash = hashlib.sha256(open(archivo, 'rb').read())
            hashes.append(hash.hexdigest())
    elif tipoHash == "SHA512":
        for archivo in archivos:
            hash = hashlib.sha512(open(archivo, 'rb').read())
            hashes.append(hash.hexdigest())


    if comprueba == False:
        logging.debug("Guardando nuevos hashes en el archivo de cofiguración")
        text_file = open("/etc/SSII-PAI1/hashes.cfg", "wb")
        stringAguardar = ""
        for hash in hashes:
            stringAguardar = stringAguardar+"{}\n".format(hash)
        stringAguardar = stringAguardar[:-1]

        logging.debug("hashesqueseguardanencryptados {}".format(stringAguardar))
        encrypted = fernet.encrypt(stringAguardar.encode())
        text_file.write(encrypted)
        text_file.close()

    else:
        compruebaSHAs(tipoHash, archivos)










def compruebaSHAs(tipoHash, archivos):
    file = open("/etc/SSII-PAI1/hashes.cfg","rb")
    encrypted = file.read()
    file.close()
    logging.debug("Encrypted: {}".format(encrypted))
    decrypted = fernet.decrypt(encrypted)
    logging.debug("Decrypted {}".format(decrypted.decode("utf-8")))
    hashesGuardados = []
    for line in decrypted.decode("UTF-8").split('\n'):
        logging.debug(line)
        hashesGuardados.append(line.strip("\n"))

    hahesArchivos = []
    if tipoHash == "SHA1":
        for archivo in archivos:
            hash = hashlib.sha1(open(archivo,'rb').read())
            hahesArchivos.append(hash.hexdigest())

    elif tipoHash == "MD5":
        for archivo in archivos:
            hash = hashlib.md5(open(archivo,'rb').read())
            hahesArchivos.append(hash.hexdigest())
    elif tipoHash == "SHA256":
        for archivo in archivos:
            hash = hashlib.sha256(open(archivo,'rb').read())
            hahesArchivos.append(hash.hexdigest())
    elif tipoHash == "SHA512":
        for archivo in archivos:
            hash = hashlib.sha512(open(archivo,'rb').read())
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



def main():
    while True:
        ConfigFile()
        sleep(tiempoEsperaDemonio)

pid = "/tmp/test.pid"
daemon = Daemonize(app="PAI1", pid=pid, action=main())
daemon.start()


