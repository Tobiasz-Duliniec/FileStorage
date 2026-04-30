import funcs.funcs as funcs
import os


class File:
    def __init__(self, public_filename:str, internal_filename:str, owner_uuid:str, owner_username:str, shareURL:str|None = None):
        self.public_filename = public_filename
        self.internal_filename = internal_filename
        self.owner_uuid = owner_uuid
        self.owner_username = owner_username
        self.shareURL = shareURL
        self.file_size = self.__read_file_size()
    
    def __read_file_size(self):
        return funcs.convert_bytes_to_megabytes(os.path.getsize(os.path.join('files', self.owner_uuid, self.internal_filename)))
