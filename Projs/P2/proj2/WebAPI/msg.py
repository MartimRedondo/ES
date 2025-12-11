from ImportPaths import *

class RegisterData(BaseModel):
    name: str
    email: EmailStr
    password: str
    public_key: str 

class LoginData(BaseModel):
    username: EmailStr
    password: str  

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"

class User(BaseModel):
    email: EmailStr

class UploadData(BaseModel):
    filename: str
    encrypted_file: str  
    encrypted_key: str   

class WriteData(BaseModel):
    filename: str        
    encrypted_file: str  
    encrypted_key: str 

class ReadFileResponse(BaseModel):
    encrypted_file: str
    encrypted_key: str 

class FolderMetadata(BaseModel):
    type: str  
    contents: Dict[str, Any] = {}
    size: Optional[int] = None
    mime: Optional[str] = None

class ListFilesResponse(BaseModel):
    files: List[str]
    folders: List[str]

class ShareInitRequest(BaseModel):
    filename: str
    target_email: str

class ShareRequest(BaseModel):
    filename: str
    target_email: str
    permissions: List[str] 

class ShareCompleteRequest(BaseModel):
    filename: str
    target_email: str
    encrypted_key_for_target: str 
    permissions: List[str]

class DeleteFileRequest(BaseModel):
    filename: str

class AppendData(BaseModel):
    filename: str       
    encrypted_file: str 
    encrypted_key: str  