#Hash test --> md5 = hashlib.md5(data).hexdigest()
import os
import sys
import argparse
import datetime
import signal
import struct
import hashlib
import subprocess
from sys import platform as _platform
import ntpath

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

EndOfChain = 0x0fffffff
EndOfFile = 0x0fffffff
EmptyCluster = 0x00000000
DamagedCluster = 0x0ffffff7
ValidBytesPerSector = [512, 1024, 2048, 4096]

MD5HashValue = ''

JPGHeader = ['JPG Header', 0xFFD8FFE0, 4]
JPGFooter = ['JPG Footer', 0xFFD9FFE0, 4]
BMPHeader = ['BMP Header', 0x4D42, 2]
PNGHeader = ['PNG Header', 0x89504E470D0A1A0A, 8]
PNGFooter = ['PNG Footer', 0x49454E44AE426082, 8]
GIFHeader1 = ['GIF Header', 0x474946383961, 6]
GIFHeader2 = ['GIF Header', 0x474946383761, 6]
GIFFooter = ['GIF Header', 0x3b]
GIFHeadChunk = []
PNGHeadChunk = []
BMPChunk = []
PNGFootChunk = []
PNGData = []
StartOffset = ''
EndOffset = ''
PNGFootStart = 0
PNGFootEnd = 0

JPGHeaderOffsets = []
JPGFooterOffsets = []
PNGHeaderOffsets = []
PNGFooterOffsets = []
GIFHeaderOffsets = []
GIFFooterOffsets = []
BMPHeaderOffsets = []




# </editor-fold>


class NotValidBootSector(Exception):
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


def HashMD5(file, block_size=2 ** 20):
    if (debug >= 1):
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
        if (debug >= 1):
            Writer('Entering ReadBootSector:')
        with open(volume, "rb") as f:
            bytes = f.read(BootSectorSize)
            BytesPerSector = struct.unpack("<H", bytes[11:13])[0]
            if (BytesPerSector not in ValidBytesPerSector):
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
    global BootSector
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
        if (debug >= 1):
            print('Entering ReadBootSector:')
        with open(volume, "rb") as f:
            bytes = f.read(BootSectorSize)
            BytesPerSector = struct.unpack("<H", bytes[11:13])[0]
            if (BytesPerSector not in ValidBytesPerSector):
                print('Error: This is not a FAT32 drive.')
            SectorsPerCluster = struct.unpack("<b", bytes[13:14])[0]
            ReservedSectorCount = struct.unpack("<H", bytes[14:16])[0]
            NumberOfFATs = struct.unpack("<b", bytes[16:17])[0]
            TotalSectors = struct.unpack("i", bytes[32:36])[0]
            FAT32Size = struct.unpack("i", bytes[36:40])[0]
            RootCluster = struct.unpack("i", bytes[44:48])[0]
            FSInfoSector = struct.unpack("<H", bytes[48:50])[0]

            #Calculate some values
            ClusterSize = SectorsPerCluster * BytesPerSector
            TotalFAT32Sectors = FAT32Size * NumberOfFATs
            TotalFAT32Bytes = FAT32Size * BytesPerSector

            DataAreaStart = ReservedSectorCount + TotalFAT32Sectors
            DataAreaEnd = TotalSectors - 1  #Base 0
            #Double Check per MS Documentation
            #FirstDataSector = BPB_ReservedSecCnt + (BPB_NumFATs * FATSz) + RootDirSectors;
            FirstDataSector = ReservedSectorCount + (NumberOfFATs * FAT32Size) + RootDirSectors
            if (debug >= 1):
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


def DriveLetter(drive):
    status = True
    error = ''

    try:
        if os.name == 'posix':
            driveletter = ('/dev/' + drive)
        elif os.name == 'nt':
            driveletter = ('\\.\%s:' % drive)
    except:
        status = False
        error = 'Cannot convert Drive Letter.'
    finally:
        return status, error, driveletter


def find_missing_range(numbers, min, max):
    expected_range = set(range(min, max + 1))
    return sorted(expected_range - set(numbers))


def numbers_as_ranges(numbers):
    ranges = []
    for number in numbers:
        if ranges and number == (ranges[-1][-1] + 1):
            ranges[-1] = (ranges[-1][0], number)
        else:
            ranges.append((number, number))
    return ranges


def format_ranges(ranges):
    range_iter = (("%d" % r[0] if r[0] == r[1] else "%d-%d" % r) for r in ranges)
    return "(" + ", ".join(range_iter) + ")"


def SearchFAT(volume, FATOffset, FirstCluster):
    status = True
    error = ''
    global ReadClusterList

    try:
        if (debug >= 1):
            print('Entering SearchFAT:')
            print('\tFirstCluster passed in: ' + str(FirstCluster))
            print('\tVolume passed in: ' + str(volume))

        nextcluster = FirstCluster
        ReadClusterList.append(nextcluster)
        y = 0
        with open(volume, "rb") as f:
            f.seek(FATOffset * BytesPerSector)
            bytes = f.read(TotalFAT32Bytes)
            if (debug >= 2):
                print('\tSeeking to FAT Offset (Bytes): ' + str(FATOffset * BytesPerSector))
            while (y <= TotalFAT32Bytes):
                y += 4
                chunk = bytes[nextcluster * 4:nextcluster * 4 + 4]
                nextcluster = struct.unpack("<i", chunk)[0]
                if (debug >= 3):
                    print('\tCluster Read [Length]: ' + '[' + str(len(chunk)) + ']' + str(chunk))
                if (debug >= 2):
                    print('\tNext Cluster: ' + str(nextcluster))
                if (nextcluster != 268435455):
                    ReadClusterList.append(nextcluster)
                else:
                    break
        if (debug >= 2):
            print('\tCluster List: ' + str(ReadClusterList))
            #return ReadClusterList
    except:
        error = 'Error: Cannot Search FAT.'
        status = False
    finally:
        return status, error


def ReadData(volume, clusterlist, size):
    status = True
    error = ''
    global FileData
    try:
        if (debug >= 1):
            print('Entering ReadData:')
        if (debug >= 2):
            print('Volume Passed in: ' + str(volume))
            print('Clusterlist Passed in: ' + str(clusterlist))
            print('Size in: ' + str(size))
        readchunk = bytearray()
        with open(volume, "rb") as f:
            for cluster in clusterlist:  #New Offset is 2 (Cluster)
                seeker = (cluster * ClusterSize + (DataAreaStart * BytesPerSector) - 2 * ClusterSize)
                f.seek(seeker)  #Each ClusterNum - 2 (Offset) * Bytes per cluster + (DataAreaStart * BytesPerSector)
                if (debug >= 2):
                    print('\tSeeking to Cluster (Bytes) [Cluster]: ' + '[' + str(cluster) + ']' + str(seeker))
                readchunk += f.read(ClusterSize)
            FileData = readchunk[0:size]
            if (debug >= 3):
                print('\tFile Data: ' + str(FileData))
    except:
        error = ('Error: Cannot Read Data.')
        status = False
    finally:
        return status, error


def WriteDatatoFile(file, filedata):
    status = True
    error = ''
    global FileData
    global MD5HashValue
    try:
        if (debug >= 1):
            print('Entering WriteDatatoFile:')
        if not (FileData == ''):
            with open(file, "wb") as f:
                f.write(FileData)
            md5 = hashlib.md5()
            md5.update(FileData)
            MD5HashValue = md5.hexdigest()
        else:
            error = 'File Data is Emtpy.'
    except:
        error = 'Error: Cannot Write Data.'
        status = False
    finally:
        return status, error


def SearchGIFHeader(volume):
    status = True
    error = ''
    global BytesPerSector
    global FirstDataSector
    global GIFHeadChunk
    counter = 0

    try:
        if (debug >= 1):
            print('Entering SearchGIFHeader:')  #4198400
        if (debug >= 2):
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            bytes = f.read(BytesPerSector)

            while (bytes != ''):
                firstchars = bytes[0:6]
                if (firstchars == b'GIF89a'):
                    if (debug >= 2):
                        print('GIF Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                    GIFHeadChunk.append(bytes)
                    bytes = f.read(BytesPerSector)
                    while (struct.unpack(">Q", bytes[0:8])[0] != 0x89504E470D0A1A0A) and (
                        struct.unpack(">H", bytes[0:2])[0] != 0xFFD9) and (
                        struct.unpack(">H", bytes[0:2])[0] != 0x424D):  #Not JPG Start, Not PNG Start, Not BMP Start
                        GIFHeadChunk.append(bytes)
                        bytes = f.read(BytesPerSector)
                    if (debug >= 2):
                        print('\tAlternate header found.')
                    break
                else:
                    bytes = f.read(BytesPerSector)
                    counter += 512
            if (debug >= 2):
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
        if (debug >= 1):
            print('Entering SearchPNGHeader:')
        if (debug >= 2):
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            bytes = f.read(BytesPerSector)

            while (bytes != ''):
                firstchars = struct.unpack(">Q", bytes[0:8])[0]
                if (firstchars == 0x89504E470D0A1A0A):
                    if (debug >= 2):
                        print('PNG Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                    PNGHeadChunk.append(bytes)
                    bytes = f.read(BytesPerSector)
                    while (bytes[0:6] != b'GIF89a') and (struct.unpack(">H", bytes[0:2])[0] != 0xFFD9) and (
                        struct.unpack(">H", bytes[0:2])[0] != 0x424D):  #Not JPG Start, Not PNG Start, Not BMP Start
                        PNGHeadChunk.append(bytes)
                        bytes = f.read(BytesPerSector)
                    if (debug >= 2):
                        print('\tAlternate header found.')
                    break
                else:
                    bytes = f.read(BytesPerSector)
                    counter += 512
            if (debug >= 2):
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
    global BMPChunk
    counter = 0

    try:
        if (debug >= 1):
            print('Entering SearchBMPHeader:')
        if (debug >= 2):
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            bytes = f.read(BytesPerSector)

            while (bytes != ''):
                firstchars = struct.unpack(">H", bytes[0:2])[0]
                if (firstchars == 0x424D):
                    BMPFilesize = struct.unpack("<H", bytes[2:4])[0]
                    if (debug >= 2):
                        print('\tBMP Header found at offset: ' + str((BytesPerSector * FirstDataSector) + counter))
                        print('\tBMP Filesize: ' + str(BMPFilesize))
                    BMPChunk = bytes
                    BMPChunk += f.read(BMPFilesize - 512)
                    break
                else:
                    bytes = f.read(BytesPerSector)
                    counter += 512
            if (debug >= 2):
                print('\tBMP First Chunk: ' + str(BMPChunk))
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

    try:
        if (debug >= 1):
            print('Entering SearchPNGFooter:')
        if (debug >= 2):
            print('\tVolume Passed in: ' + str(volume))
        with open(volume, "rb") as f:
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(BytesPerSector * FirstDataSector))
            f.seek(BytesPerSector * FirstDataSector)
            bytes = f.read(BytesPerSector)

            while (bytes != ''):
                x = 0
                while (x != 512 - 8):
                    firstchars = struct.unpack(">Q", bytes[x:8+x])[0]
                    if (firstchars == 0x49454E44AE426082):
                        PNGFootEnd = (BytesPerSector * FirstDataSector + counter + x + 8) #Data Offset + Number of Sectors + X offset + 8 for end of data
                        if (debug >= 2):
                            print('\tPNG Footer end located at offset [Bytes]: ' + str(BytesPerSector * FirstDataSector + counter + x + 8))
                        offsetfromsector = (x+8)
                        breaker = True
                        break
                    else:
                        x += 1
                if (breaker):
                    break
                counter += 512
                bytes = f.read(BytesPerSector)


            while (True):
                f.seek(PNGFootEnd - offsetfromsector - backwards - 16)
                bytes = f.read(16)
                if (bytes != b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'):
                    backwards += 512
                else:
                    PNGFootStart = PNGFootEnd - offsetfromsector - backwards
                    if (debug >= 2):
                        print('\tPNG Footer start located at offset [Bytes]: ' + str(PNGFootStart))
                    break

            f.seek(PNGFootStart)
            if (debug >= 2):
                print('\tSeeking to First Data Sector [Bytes]: ' + str(PNGFootStart))
            PNGFootChunk.append(f.read(PNGFootEnd - PNGFootStart))
            PNGData = PNGHeadChunk + PNGFootChunk
            if (debug >= 2):
                print('\tPNG First Chunk: ' + str(PNGHeadChunk))
                print('\tPNG Last Chunk: ' + str(PNGFootChunk))
                print('\tPNG Chunk: ' + str(PNGData))

            print(hashlib.md5(PNGData).hexdigest())




    except:
        error = 'Error: Cannot Find Valid Headers.'
        status = False
    finally:
        return status, error


def signal_handler(signal, frame):
    print('Ctrl+C pressed. Exiting.')
    sys.exit(0)


def Writer(text):
    print('\t' + text)


def Header():
    print('')
    print('+------------------------------------------------------------------------+')
    print('|FAT32 File Carving Utility.                                             |')
    print('+-------------------------------------------------------------------------')
    print('|Author: Tahir Khan - tkhan9@gmu.edu                                     |')
    print('+------------------------------------------------------------------------+')
    print('  Date Run: ' + str(datetime.datetime.now()))
    print('+------------------------------------------------------------------------+')


def Failed(error):
    print('  * Error: ' + str(error))
    print('+------------------------------------------------------------------------+')
    print('| Failed.                                                                |')
    print('+------------------------------------------------------------------------+')
    sys.exit(1)


def Completed():
    print('| Completed.                                                             |')
    print('+------------------------------------------------------------------------+')
    sys.exit(0)



signal.signal(signal.SIGINT, signal_handler)


def main(argv):
    try:
        global debug
        global MD5HashValue
        #parse the command-line arguments
        parser = argparse.ArgumentParser(description="A FAT32 file system carver.",
                                         add_help=True)
        parser.add_argument('-p', '--path', help='The path to write the files to.', required=False)
        parser.add_argument('-v', '--volume', help='The volume to read from.', required=True)
        parser.add_argument('-d', '--debug', help='The level of debugging.', required=False)
        parser.add_argument('--version', action='version', version='%(prog)s 1.5')
        args = parser.parse_args()
        if (args.volume):
            volume = args.volume
        if (args.debug):
            debug = args.debug
            debug = int(debug)
        if _platform == "linux" or _platform == "linux2":
            os = 'Linux'
        elif _platform == "darwin":
            os = 'Mac'
        elif _platform == "win32":
            os = 'Windows'
        if (debug >= 1):
            print('Entered main:')
            print('\tVolume: ' + str(volume))
            print('\tOperating System: ' + str(os))
            print('\tDebug Level: ' + str(debug))
            #if (os == 'Windows'):
            #    print ('Error: System not supported.')
            #    sys.exit(1)



        Header()
        status, error = IdentifyFileSystem(volume)
        if (status):
            print('| [+] Identifying File System.                                             |')
        else:
            print('| [-] Unsupported File System.                                             |')
            Failed(error)
        status, error = ReadBootSector(volume)
        if (status):
            print('| [+] Reading Boot Sector.                                                 |')
        else:
            print('| [-] Reading Boot Sector.                                                 |')
            Failed(error)
        status, error = SearchGIFHeader(volume)
        if (status):
            print('| [+] Searching for GIF Data.                                              |')
        else:
            print('| [-] Searching for GIF Data.                                              |')
            Failed(error)
        status, error = SearchPNGHeader(volume)
        if (status):
            print('| [+] Searching for Header PNG Data.                                       |')
        else:
            print('| [-] Searching for Header PNG Data.                                       |')
            Failed(error)
        status, error = SearchBMPHeader(volume)
        if (status):
            print('| [+] Searching for BMP Data.                                              |')
        else:
            print('| [-] Searching for BMP Data.                                              |')
            Failed(error)
        status, error = SearchPNGFooter(volume)
        if (status):
            print('| [+] Searching for PNG Footer Data.                                       |')
        else:
            print('| [-] Searching for PNG Footer Data.                                       |')
            Failed(error)
            Completed()
    except:
        print()


main(sys.argv[1:])