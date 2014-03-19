#TODO Create list of images found to handle more than 1 image per type
#TODO Create file creator that writes out files with counter, or maybe just hashes
import sys
import argparse
import datetime
import signal
import struct
import hashlib
from sys import platform as _platform

debug = 0
#References Microsoft's FAT General Overview 1.03
# <editor-fold desc="Boot Sector Variables">

BytesPerSector = ''  #Offset 11 - 2 bytes
SectorsPerCluster = ''  #Offset 13 - 1 byte
ReservedSectorCount = ''  #Offset 14 - 2 bytes
NumberOfFATs = ''  #Offset 16 - 1 byte
TotalSectors = ''  #Offset 32 - 4 bytes
# Start of FAT32 Structure 
FAT32Size = ''  #Offset 36 - 4 bytes
RootCluster = ''  #Offset 44 - 4 bytes
FSInfoSector = ''  #Offset 48 - 2 bytes
ClusterSize = ''
TotalFAT32Sectors = ''
TotalFAT32Bytes = ''
DataAreaStart = ''
DataAreaEnd = ''
RootDirSectors = 0  #Always 0 for Fat32 Per MS Documentation
#FSINFO 
Signature = ''
NumberOfFreeClusters = 0
NextFreeCluster = 0
BootSectorSize = 512
# </editor-fold>

# <editor-fold desc="Global Variables">

ValidBytesPerSector = [512, 1024, 2048, 4096]

GIFHeadChunk = []
GIFFootChunk = []
GIFData = []
PNGHeadChunk = []
PNGFootChunk = []
PNGData = []
BMPData = []
JPGHeadChunk = []
JPGFootChunk = []
JPGData = []
JPGFootStart = 0
JPGFootEnd = 0
PNGFootStart = 0
PNGFootEnd = 0
GIFFootEnd = 0
GIFFootStart = 0
KnownOffsets = []
# </editor-fold>


class NotValidBootSector(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def HashMD5(file, block_size=2 ** 20):
    if debug >= 1:
        print('Entering HashMD5:')
    md5 = hashlib.md5()
    with open(file, 'rb') as f:
        while True:
            data = f.read(block_size)
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()


def IdentifyFileSystem(volume):
    status = True
    error = ''
    global BootSectorSize
    global ValidBytesPerSector

    try:
        if debug >= 1:
            Writer('Entering ReadBootSector:')
        with open(volume, "rb") as f:
            byte = f.read(BootSectorSize)
            BytesPerSector = struct.unpack("<H", byte[11:13])[0]
            if BytesPerSector not in ValidBytesPerSector:
                raise NotValidBootSector('Only FAT32 supported.')

    except:
        status = False
        error = 'Cannot read Boot Sector.'
    finally:
        return status, error


def ReadBootSector(volume):
    # <editor-fold desc="Global Variables">
    global DataAreaStart
    global BytesPerSector
    global SectorsPerCluster
    global ReservedSectorCount
    global NumberOfFATs
    global TotalSectors
    # Start of FAT32 Structure
    global FAT32Size
    global RootCluster
    global FSInfoSector
    global ClusterSize
    global TotalFAT32Sectors
    global TotalFAT32Bytes
    global DataAreaStart
    global DataAreaEnd
    global FirstDataSector
    # </editor-fold>
    status = True
    error = ''

    # Reads the specified bytes from the drive
    try:
        if debug >= 1:
            print('Entering ReadBootSector:')
        with open(volume, "rb") as f:
            byte = f.read(BootSectorSize)
            BytesPerSector = struct.unpack("<H", byte[11:13])[0]
            if BytesPerSector not in ValidBytesPerSector:
                print('Error: This is not a FAT32 drive.')
            SectorsPerCluster = struct.unpack("<b", byte[13:14])[0]
            ReservedSectorCount = struct.unpack("<H", byte[14:16])[0]
            NumberOfFATs = struct.unpack("<b", byte[16:17])[0]
            TotalSectors = struct.unpack("i", byte[32:36])[0]
            FAT32Size = struct.unpack("i", byte[36:40])[0]
            RootCluster = struct.unpack("i", byte[44:48])[0]
            FSInfoSector = struct.unpack("<H", byte[48:50])[0]

            #Calculate some values
            ClusterSize = SectorsPerCluster * BytesPerSector
            TotalFAT32Sectors = FAT32Size * NumberOfFATs
            TotalFAT32Bytes = FAT32Size * BytesPerSector

            DataAreaStart = ReservedSectorCount + TotalFAT32Sectors
            DataAreaEnd = TotalSectors - 1  #Base 0
            FirstDataSector = ReservedSectorCount + (NumberOfFATs * FAT32Size) + RootDirSectors
            if debug >= 1:
                print('\tBytes per Sector: ' + str(BytesPerSector))
                print('\tSectors per Cluster: ' + str(SectorsPerCluster))
                print('\tCluster Size: ' + str(ClusterSize))
                print('\tRoot Cluster: ' + str(RootCluster))
                print('\tFSInfo Cluster: ' + str(FSInfoSector))
                print('\tTotal Sectors: ' + str(TotalSectors))
                print('\tReserved Sector Count: ' + str(ReservedSectorCount))
                print('\tReserved Sectors: ' + '0  - ' + str(ReservedSectorCount - 1))
                print('\tFAT Offset: ' + str(ReservedSectorCount))
                print('\tFAT Offset (Bytes): ' + str(ReservedSectorCount * BytesPerSector))
                print('\tNumber of FATs: ' + str(NumberOfFATs))
                print('\tFAT32 Size: ' + str(FAT32Size))
                print('\tTotal FAT32 Sectors: ' + str(TotalFAT32Sectors))
                print('\tFAT Sectors: ' + str(ReservedSectorCount) + ' - ' + str(
                    (ReservedSectorCount - 1) + (FAT32Size * NumberOfFATs)))
                print('\tData Area: ' + str(DataAreaStart) + ' - ' + str(DataAreaEnd))
                print('\tData Area Offset (Bytes): ' + str(DataAreaStart * BytesPerSector))
                #print('\tRoot Directory: ' + str(DataAreaStart) + ' - ' + str(DataAreaStart + 3))
                #Extra Testing
                print('\t   First Data Sector: ' + str(FirstDataSector))
    except IOError:
        status = False
        error = 'Volume ' + str(volume) + ' does not exist.'
    except:
        status = False
        error = 'Cannot read Boot Sector.'
    finally:
        return status, error


def WriteDatatoFile(path):
    status = True
    error = ''
    global JPGData
    global PNGData
    global BMPData
    global GIFData
    ba = b''
    path += '\\'

    try:
        if debug >= 1:
            print('Entering WriteDatatoFile:')
        if debug >= 2:
            print('\tPath entered: ' + str(path))
        with open(path + 'image.jpg', "wb") as f:
            for b in JPGData:
                ba += b
            if debug >= 2:
                print('\tRaw byte data: ' + str(ba))
            f.write(ba)
        ba = b''
        with open(path + 'image.png', "wb") as f:
            for b in PNGData:
                ba += b
            if debug >= 2:
                print('\tRaw byte data: ' + str(ba))
            f.write(ba)
        ba = b''
        with open(path + 'image.bmp', "wb") as f:
            for b in BMPData:
                ba += b
            if debug >= 2:
                print('\tRaw byte data: ' + str(ba))
            f.write(ba)
        ba = b''
        with open(path + 'image.gif', "wb") as f:
            for b in GIFData:
                ba += b
            if debug >= 2:
                print('\tRaw byte data: ' + str(ba))
            f.write(ba)
    except:
        error = 'Error: Cannot Write Data.'
        status = False
    finally:
        return status, error


def SearchGIFs(volume):
    status = True
    error = ''
    counter = 0
    slider = 0
    byte = b''
    data = []
    gifs = []
    endofgif = False

    if debug >= 1:
        print('Entering SearchGIFs:')
    if debug >= 2:
        print('\tVolume Passed in: ' + str(volume))
    with open(volume, "rb") as f:
        if debug >= 2:
            print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
        f.seek(BytesPerSector * FirstDataSector)
        sector = f.read(BytesPerSector)
        while sector != '':
        #Identify GIF Header
            if sector[0:6] == b'GIF89a':
                if debug >= 3:
                    print('\tGIF Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                #Check for contig GIF
                while (slider != 512):

                    if (struct.unpack(">Q", sector[0:8])[0] == 0x89504E470D0A1A0A) and (struct.unpack(">H", sector[0:2])[0] == 0xFFD8) and (struct.unpack(">H", sector[0:2])[0] == 0x424D):
                        endofgif = False
                        break
                    else:
                        byte = sector[slider:slider+1]
                    if byte != b'\x3b':
                        data.append(byte)
                        slider += 1
                    else:
                        endofgif = True
                        print (data)
                        break
            else:
                sector = f.read(BytesPerSector)
            if endofgif:
                gifs.append(data)
                break

    sys.exit()


def SearchGIFHeader(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global GIFHeadChunk
    counter = 0
    breaker = False
    x = 0

    try:
        if debug >= 1:
            print('Entering SearchGIFHeader:')  #4198400
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)

            while byte != '':
                firstchars = byte[0:6]
                if firstchars == b'GIF89a':
                    if debug >= 2:
                        print('\tGIF Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                    GIFHeadChunk.append(byte)
                    byte = f.read(BytesPerSector)
                    while (struct.unpack(">Q", byte[0:8])[0] != 0x89504E470D0A1A0A) and (
                                struct.unpack(">H", byte[0:2])[0] != 0xFFD8) and (
                                struct.unpack(">H", byte[0:2])[0] != 0x424D):  #Not JPG Start, Not PNG Start, Not BMP Start
                        GIFHeadChunk.append(byte)
                        byte = f.read(BytesPerSector)
                        if byte == '':
                            break

                        if debug >= 2:
                            print('\tAlternate header found.')
                    break
                else:
                    if breaker:
                        break
                    byte = f.read(BytesPerSector)
                    counter += BytesPerSector
            if debug >= 2:
                print('\tGIF First Chunk: ' + str(GIFHeadChunk))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchPNGHeader(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global PNGHeadChunk
    counter = 0

    try:
        if debug >= 1:
            print('Entering SearchPNGHeader:')
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)

            while byte != '':
                firstchars = struct.unpack(">Q", byte[0:8])[0]
                if firstchars == 0x89504E470D0A1A0A:
                    if debug >= 2:
                        print('PNG Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                    PNGHeadChunk.append(byte)
                    byte = f.read(BytesPerSector)
                    while (byte[0:6] != b'GIF89a') and (struct.unpack(">H", byte[0:2])[0] != 0xFFD8) and (
                                struct.unpack(">H", byte[0:2])[
                                    0] != 0x424D):  #Not JPG Start, Not PNG Start, Not BMP Start
                        PNGHeadChunk.append(byte)
                        byte = f.read(BytesPerSector)
                    if debug >= 2:
                        print('\tAlternate header found.')
                    break
                else:
                    byte = f.read(BytesPerSector)
                    counter += BytesPerSector
            if debug >= 2:
                print('\tPNG First Chunk: ' + str(PNGHeadChunk))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchBMPHeader(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global BMPData
    counter = 0

    try:
        if debug >= 1:
            print('Entering SearchBMPHeader:')
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)

            while byte != '':
                firstchars = struct.unpack(">H", byte[0:2])[0]
                if firstchars == 0x424D:
                    BMPFilesize = struct.unpack("<H", byte[2:4])[0]
                    if debug >= 2:
                        print('\tBMP Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                        print('\tBMP Filesize: ' + str(BMPFilesize))
                    BMPData.append(byte)
                    BMPData.append(f.read(BMPFilesize - BytesPerSector))
                    break
                else:
                    byte = f.read(BytesPerSector)
                    counter += BytesPerSector
            if debug >= 2:
                print('\tBMP First Chunk: ' + str(BMPData))
                print('\tBMP MD5 Hash: ' + Hasher(BMPData, 'md5'))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchGIFFooter(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global GIFFootChunk
    global GIFHeadChunk
    global GIFFootEnd
    global GIFFootStart
    global GIFData
    counter = 0
    breaker = False
    backwards = 0
    offsetfromsector = 0

    try:
        if debug >= 1:
            print('Entering SearchGIFFooter:')
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)
            while byte != '':
                x = BytesPerSector
                if (struct.unpack(">Q", byte[0:8])[0] != 0x89504E470D0A1A0A) and (
                            struct.unpack(">H", byte[0:2])[0] != 0xFFD8) and (
                            struct.unpack(">H", byte[0:2])[0] != 0x424D) and (byte[0:6] != b'GIF89a'):
                    while x != 0:
                        if byte[
                           BytesPerSector - 16:BytesPerSector] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                            firstchars = struct.unpack(">H", byte[x - 2:x])[0]
                            if firstchars == 0x003B:
                                GIFFootEnd = (BytesPerSector * FirstDataSector + counter + x - 1)
                                offsetfromsector = (x - 1)
                                if debug >= 2:
                                    print('\tGIF Footer end located at offset [Bytes]: ' + str(GIFFootEnd))
                                    print('\tOffset from previous sector [Bytes]: ' + str(offsetfromsector))
                                breaker = True
                                break
                            else:
                                x -= 2
                        else:
                            break
                    if breaker:
                        break
                    counter += BytesPerSector
                    byte = f.read(BytesPerSector)
                    if debug >= 3:
                        print('\tNext sector: ' + str(BytesPerSector * FirstDataSector + counter))
                else:
                    counter += BytesPerSector
                    byte = f.read(BytesPerSector)

            while True:
                f.seek(GIFFootEnd - offsetfromsector - backwards - 16)
                byte = f.read(16)
                if byte != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    backwards += BytesPerSector
                else:
                    GIFFootStart = GIFFootEnd - offsetfromsector - backwards
                    if debug >= 2:
                        print('\tGIF Footer start located at offset [Bytes]: ' + str(GIFFootStart))
                    break
            f.seek(GIFFootStart)
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(GIFFootStart))

            GIFFootChunk.append(f.read(GIFFootEnd + 1 - GIFFootStart))
            GIFData = GIFHeadChunk + GIFFootChunk
            if debug >= 2:
                print('\tGIF First Chunk: ' + str(GIFHeadChunk))
                print('\tGIF Last Chunk: ' + str(GIFFootChunk))
                print('\tGIF Chunk: ' + str(GIFData))
                print('\tGIF MD5 Hash: ' + str(Hasher(GIFData, 'md5')))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchPNGFooter(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global PNGFootChunk
    global PNGHeadChunk
    global PNGFootEnd
    global PNGFootStart
    global PNGData
    counter = 0
    breaker = False
    backwards = 0
    offsetfromsector = 0

    try:
        if debug >= 1:
            print('Entering SearchPNGFooter:')
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)

            while byte != '':
                x = 0
                while x != BytesPerSector - 8:
                    firstchars = struct.unpack(">Q", byte[x:8 + x])[0]
                    if firstchars == 0x49454E44AE426082:
                        PNGFootEnd = (BytesPerSector * FirstDataSector + counter + x + 8) #Data Offset + Number of Sectors + X offset + 8 for end of data
                        if debug >= 2:
                            print('\tPNG Footer end located at offset [Bytes]: ' + str(BytesPerSector * FirstDataSector + counter + x + 8))
                        offsetfromsector = (x+8)
                        breaker = True
                        break
                    else:
                        x += 1
                if breaker:
                    break
                counter += BytesPerSector
                byte = f.read(BytesPerSector)

            while True:
                f.seek(PNGFootEnd - offsetfromsector - backwards - 16)
                byte = f.read(16)
                if byte != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    backwards += BytesPerSector
                else:
                    PNGFootStart = PNGFootEnd - offsetfromsector - backwards
                    if debug >= 2:
                        print('\tPNG Footer start located at offset [Bytes]: ' + str(PNGFootStart))
                    break

            f.seek(PNGFootStart)
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(PNGFootStart))
            PNGFootChunk.append(f.read(PNGFootEnd - PNGFootStart))
            PNGData = PNGHeadChunk + PNGFootChunk
            if debug >= 2:
                print('\tPNG First Chunk: ' + str(PNGHeadChunk))
                print('\tPNG Last Chunk: ' + str(PNGFootChunk))
                print('\tPNG Chunk: ' + str(PNGData))
                print('\tPNG MD5 Hash: ' + str(Hasher(PNGData, 'md5')))




    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchJPGHeader(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global JPGHeadChunk
    counter = 0

    try:
        if debug >= 1:
            print('Entering SearchJPGHeader:')  #4198400
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)

            while byte != '':
                firstchars = struct.unpack(">H", byte[0:2])[0]
                if firstchars == 0xFFD8:
                    if debug >= 2:
                        print('JPG Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                    JPGHeadChunk.append(byte)
                    break
                else:
                    byte = f.read(BytesPerSector)
                    counter += BytesPerSector

            if debug >= 2:
                print('\tJPG First Chunk: ' + str(JPGHeadChunk))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def SearchJPGFooter(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global JPGFootChunk
    global JPGHeadChunk
    global JPGFootEnd
    global JPGFootStart
    global JPGData
    counter = 0
    breaker = False
    backwards = 0
    offsetfromsector = 0

    try:
        if debug >= 1:
            print('Entering SearchJPGFooter:')
        if debug >= 2:
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            byte = f.read(BytesPerSector)
            while byte != '':
                x = BytesPerSector
                if (struct.unpack(">Q", byte[0:8])[0] != 0x89504E470D0A1A0A) and (
                            struct.unpack(">H", byte[0:2])[0] != 0xFFD8) and (
                            struct.unpack(">H", byte[0:2])[0] != 0x424D) and (byte[0:6] != b'GIF89a'):
                    while x != 0:
                        if byte[
                           BytesPerSector - 16:BytesPerSector] == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                            firstchars = struct.unpack(">H", byte[x - 2:x])[0]
                            if firstchars == 0xFFD9:
                                JPGFootEnd = (BytesPerSector * FirstDataSector + counter + x - 1)
                                offsetfromsector = (x - 1)
                                if debug >= 2:
                                    print('\tJPG Footer end located at offset [Bytes]: ' + str(JPGFootEnd))
                                    print('\tOffset from previous sector [Bytes]: ' + str(offsetfromsector))
                                breaker = True
                                break
                            else:
                                x -= 2
                        else:
                            break
                    if breaker:
                        break
                    counter += BytesPerSector
                    byte = f.read(BytesPerSector)
                    if debug >= 3:
                        print('\tNext sector: ' + str(BytesPerSector * FirstDataSector + counter))
                else:
                    counter += BytesPerSector
                    byte = f.read(BytesPerSector)

            while True:
                f.seek(JPGFootEnd - offsetfromsector - backwards - 16)
                byte = f.read(16)
                if byte != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00':
                    backwards += BytesPerSector
                else:
                    JPGFootStart = JPGFootEnd - offsetfromsector - backwards
                    if debug >= 2:
                        print('\tJPG Footer start located at offset [Bytes]: ' + str(JPGFootStart))
                    break
            f.seek(JPGFootStart)
            if debug >= 2:
                print('\tSeeking to First Data Sector [Bytes]: ' + str(JPGFootStart))

            JPGFootChunk.append(f.read(JPGFootEnd + 1 - JPGFootStart))
            if len(JPGHeadChunk) == len(JPGFootChunk):
                JPGData = JPGFootChunk
            else:
                JPGData = JPGHeadChunk + JPGFootChunk
            if debug >= 2:
                print('\tJPG First Chunk: ' + str(JPGHeadChunk))
                print('\tJPG Last Chunk: ' + str(JPGFootChunk))
                print('\tJPG Chunk: ' + str(JPGData))
                print('\tJPG MD5 Hash: ' + str(Hasher(JPGData, 'md5')))
    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def Hasher(data, hashtype):
    ba = b''
    for x in data:
        ba += bytearray(x)
    if (hashtype == 'md5'):
        return hashlib.md5(ba).hexdigest()
    elif (hashtype == 'sha1'):
        return hashlib.sha1(ba).hexdigest()


def signal_handler(signal, frame):
    print('Ctrl+C pressed. Exiting.')
    sys.exit(0)


def Writer(text):
    print('\t' + text)


def Header():
    print('')
    print('+--------------------------------------------------------------------------+')
    print('|FAT32 File Carving Utility.                                               |')
    print('+---------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                       |')
    print('+--------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+--------------------------------------------------------------------------+')


def Failed(error):
    print('  * Error: ' + str(error))
    print('+--------------------------------------------------------------------------+')
    print('| Failed.                                                                  |')
    print('+--------------------------------------------------------------------------+')
    sys.exit(1)


def FileHashes():
    global JPGData
    global PNGData
    global BMPData
    global GIFData

    print('|MD5 Hashes:                                                               |')
    print('+--------------------------------------------------------------------------+')
    print('| JPG Hash: ' + str(Hasher(JPGData, 'md5')) + '                               |')
    print('| PNG Hash: ' + str(Hasher(PNGData, 'md5')) + '                               |')
    print('| GIF Hash: ' + str(Hasher(GIFData, 'md5')) + '                               |')
    print('| BMP Hash: ' + str(Hasher(BMPData, 'md5')) + '                               |')
    print('+--------------------------------------------------------------------------+')
    print('|SHA1 Hashes:                                                              |')
    print('+--------------------------------------------------------------------------+')
    print('| JPG Hash: ' + str(Hasher(JPGData, 'sha1')) + '                       |')
    print('| PNG Hash: ' + str(Hasher(PNGData, 'sha1')) + '                       |')
    print('| GIF Hash: ' + str(Hasher(GIFData, 'sha1')) + '                       |')
    print('| BMP Hash: ' + str(Hasher(BMPData, 'sha1')) + '                       |')
    print('+--------------------------------------------------------------------------+')
    sys.exit(0)


def Completed():
    print('| [*] Completed.                                                           |')
    print('+--------------------------------------------------------------------------+')


signal.signal(signal.SIGINT, signal_handler)


def main(argv):
    try:
        global debug
        #parse the command-line arguments
        parser = argparse.ArgumentParser(description="A FAT32 file system carver.",
                                         add_help=True)
        parser.add_argument('-p', '--path', help='The path to write the files to.', required=True)
        parser.add_argument('-v', '--volume', help='The volume to read from.', required=True)
        parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
        parser.add_argument('--version', action='version', version='%(prog)s 1.5')
        args = parser.parse_args()
        if args.volume:
            volume = args.volume
        if args.path:
            path = args.path
        if args.debug:
            debug = args.debug
            debug = int(debug)
        if _platform == "linux" or _platform == "linux2":
            os = 'Linux'
        elif _platform == "darwin":
            os = 'Mac'
        elif _platform == "win32":
            os = 'Windows'
        if debug >= 1:
            print('Entered main:')
            print('\tVolume: ' + str(volume))
            print('\tOperating System: ' + str(os))
            print('\tDebug Level: ' + str(debug))
            #if (os == 'Windows'):
            #    print ('Error: System not supported.')
            #    sys.exit(1)



        Header()
        status, error = IdentifyFileSystem(volume)
        if status:
            print('| [+] Identifying File System.                                             |')
        else:
            print('| [-] Unsupported File System.                                             |')
            Failed(error)
        status, error = ReadBootSector(volume)
        if status:
            print('| [+] Reading Boot Sector.                                                 |')
        else:
            print('| [-] Reading Boot Sector.                                                 |')
            Failed(error)
        SearchGIFs(volume)
        status, error = SearchGIFHeader(volume)
        if status:
            print('| [+] Searching for GIF Header Data.                                       |')
        else:
            print('| [-] Searching for GIF Header Data.                                       |')
            Failed(error)
        status, error = SearchPNGHeader(volume)
        if status:
            print('| [+] Searching for PNG Header Data.                                       |')
        else:
            print('| [-] Searching for PNG Header Data.                                       |')
            Failed(error)
        status, error = SearchBMPHeader(volume)
        if status:
            print('| [+] Searching for BMP Header Data.                                       |')
        else:
            print('| [-] Searching for BMP Header Data.                                       |')
            Failed(error)
        status, error = SearchPNGFooter(volume)
        if status:
            print('| [+] Searching for PNG Footer Data.                                       |')
        else:
            print('| [-] Searching for PNG Footer Data.                                       |')
            Failed(error)
        status, error = SearchGIFFooter(volume)
        if status:
            print('| [+] Searching for GIF Footer Data.                                       |')
        else:
            print('| [-] Searching for GIF Footer Data.                                       |')
            Failed(error)
        status, error = SearchJPGHeader(volume)
        if status:
            print('| [+] Searching for JPG Header Data.                                       |')
        else:
            print('| [-] Searching for JPG Header Data.                                       |')
            Failed(error)
        status, error = SearchJPGFooter(volume)
        if status:
            print('| [+] Searching for JPG Footer Data.                                       |')
        else:
            print('| [-] Searching for JPG Footer Data.                                       |')
            Failed(error)
        status, error = WriteDatatoFile(path)
        if status:
            print('| [+] Writing Output.                                                      |')
        else:
            print('| [-] Writing Output.                                                      |')
            Failed(error)
        Completed()
        FileHashes()

    except:
        print()


main(sys.argv[1:])