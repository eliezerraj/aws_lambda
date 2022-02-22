from __future__ import print_function
import json
import base64
import boto3
import os
import zlib
import aws_encryption_sdk
from aws_encryption_sdk import CommitmentPolicy
from aws_encryption_sdk.internal.crypto import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk.identifiers import WrappingAlgorithm, EncryptionKeyType

REGION_NAME = os.environ['REGION_NAME'] # 'us-east-2'
RESOURCE_ID = os.environ['RESOURCE_ID'] #'cluster-2VRZ32321312321321'
enc_client = aws_encryption_sdk.EncryptionSDKClient(commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT)

kms_client = boto3.client('kms', region_name=REGION_NAME)

class MyRawMasterKeyProvider(RawMasterKeyProvider):
    #print("-------------------- MyRawMasterKeyProvider ---------------------------- " )  
    provider_id = "BC"
    def __new__(cls, *args, **kwargs):
        obj = super(RawMasterKeyProvider, cls).__new__(cls)
        return obj
    def __init__(self, plain_key):
        RawMasterKeyProvider.__init__(self)
        self.wrapping_key = WrappingKey(wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,wrapping_key=plain_key, wrapping_key_type=EncryptionKeyType.SYMMETRIC)
    def _get_raw_key(self, key_id):
        return self.wrapping_key

def lambda_handler(event, context):
    #print("Received event: " + json.dumps(event, indent=2))
    print("--------------- lambda_handler VERSION 1.7 ------------------ ")  
    output = []
    for record in event['Records']:
        #Kinesis data is base64 encoded so decode here
        
        payload=base64.b64decode(record['kinesis']['data'])
        #print("Decoded payload: " + str(payload))

        val = processDASRecord(payload)
        if len(val)>0:
            output_record = {
                'eventID': record['eventID'],
                'result': 'Ok',
                'data': val
            }
        else:
            output_record = {
                'eventID': record['eventID'],
                'result': 'Dropped',
                'data': 'this is a dropped event'
            }
        print ("Record ===> ", str(output_record) )
        output.append(output_record)

    return {'record': output}

def decrypt_decompress(payload, key):
    #print("-------------------- decrypt_decompress ---------------------------- " )  
    decrypted = decrypt_payload(payload, key)
    decrypted = zlib.decompress(decrypted, zlib.MAX_WBITS + 16)
    return decrypted
    
def decrypt_payload(payload, data_key):
    #print("-------------------- decrypt_payload ---------------------------- " )  
    my_key_provider = MyRawMasterKeyProvider(data_key)
    my_key_provider.add_master_key("DataKey")
    #Decrypt the records using the master key.
    decrypted_plaintext, header = enc_client.decrypt(
        source=payload,
        materials_manager=aws_encryption_sdk.materials_managers.default.DefaultCryptoMaterialsManager(master_key_provider=my_key_provider))
    return decrypted_plaintext

def processDASRecord(payload):
    #print("--------------------processDASRecord ---------------------------- " )  
    #print("REGION_NAME " + REGION_NAME ) 
    #print("RESOURCE_ID " + RESOURCE_ID )
    record = json.loads(payload)
    #print("record ====> " + str(record))
    if record['type'] == 'DatabaseActivityMonitoringRecords':
        #print("------------------------------------------------------------ " ) 
        dataKey = base64.b64decode(record["key"])
        try:
            data_key_decrypt_result = kms_client.decrypt(CiphertextBlob=dataKey, EncryptionContext={'aws:rds:dbc-id':RESOURCE_ID})
            #print("data_key_decrypt_result: "  + str(data_key_decrypt_result)) 
        except Exception as e:
            print("------Erro 1 ---------- " ) 
            print(e)
            raise e
        
        #print("------------------------------------------------------------ " ) 
        dbEvents = record["databaseActivityEvents"]
        try:
            plaintextEvents = decrypt_decompress(base64.b64decode(dbEvents), data_key_decrypt_result['Plaintext'])
            #print("plaintextEvents: "  + str(plaintextEvents)) 
        except Exception as e:
            print("------Erro 2 ---------- " ) 
            print(e)
            raise e

        retObj = []
        try:
            events = json.loads(plaintextEvents)
            #print("events: "  + str(events))

            for dbEvent in events['databaseActivityEventList']:
                #filter out events which you don't want to log.
                if dbEvent['type']== "heartbeat": #or  eventType == "READ":
                    #print ("Heart beat event - ignored event, dropping it.")
                    continue

                if not (dbEvent.get('command') is None):
                    eventType = dbEvent['command']
                    #use this section to log all events in separate S3 folder. 
                    #parse and write individual type of events to separate S3 folders. 
                    #s3suffix = '/' + str(todays_date.year) + '/' + str(todays_date.month) + '/' + str(todays_date.day) + '/' + rID + '.txt' 
                    #s3.put_object(Body=json.dumps(dbEvent, ensure_ascii=False), Bucket=BUCKET_NAME, Key = 'parsed/'+ eventType + s3suffix )
                    #print ("Event:", str(dbEvent) )

                retObj.append(dbEvent)

        except Exception as e:
            print("------Erro 3 ---------- " ) 
            print (e)
            raise e

        #print("------ SUCESSO ---------- " ) 
        return retObj
        
