module DNS.Transport where

import           Data.Binary.Get                 (runGet)
import           Data.Binary.Put                 (runPut)
import qualified Data.ByteString.Lazy            as BSL
import           Network.Socket                  hiding (recv, recvFrom, send,
                                                  sendTo)

import           DNS.Protocol
import           DNS.Protocol.DNSClass
import           DNS.Protocol.DNSName
import           DNS.Protocol.ResourceRecord
import           DNS.Protocol.ResourceRecordType
import           DNS.Protocol.ResponseCode

import           Parsing.BinaryBit
import           Parsing.IPAddress
import           Transport.UDP

import           Hexdump
import           Text.Pretty.Simple              (pPrint)

import qualified Data.Map.Strict                 as Map
import           Data.Word                       (Word8)
import           Protolude

data ZoneTy = ZA Word8 Word8 Word8 Word8
            | ZCName Text
type Zone = Map.Map DNSName ZoneTy

testZone :: Zone
testZone = Map.fromList [(mkDNSNameFromStr "www.google.com", ZA 127 0 0 1)]

zoneLookup :: Zone -> DNSName -> ResourceRecord
zoneLookup z q = toRR $ Map.lookup q z
  where
    toRR :: Maybe ZoneTy -> ResourceRecord
    toRR Nothing = Std $ calculateRRLength StdResourceRecord { rrName = q
                                                             , rrType = RRSOA
                                                             , rrClass = ClsInternet
                                                             , rrTTL = 0x258
                                                             , rrLength = 0
                                                             , rrData = RDSOA
                                                                          (mkDNSNameFromStr "localhost")
                                                                          (mkDNSNameFromStr "localhost")
                                                                          00000001
                                                                          0x258
                                                                          0x258
                                                                          0x258
                                                                          0x258
                                                             }
    toRR (Just (ZA o1 o2 o3 o4)) = Std $ calculateRRLength StdResourceRecord { rrName = q
                                                                             , rrType = RRA
                                                                             , rrClass = ClsInternet
                                                                             , rrTTL = 0x258
                                                                             , rrLength = 0
                                                                             , rrData = RDA $ ipAddress o1 o2 o3 o4
                                                                             }
    toRR (Just (ZCName name)) = Std $ calculateRRLength StdResourceRecord { rrName = q
                                                                          , rrType = RRCNAME
                                                                          , rrClass = ClsInternet
                                                                          , rrTTL = 0x258
                                                                          , rrLength = 0
                                                                          , rrData = RDCName $ mkDNSNameFromStr name
                                                                          }

server :: IO ()
server = do
  Just addrinfos <- head <$> getAddrInfo Nothing (Just "127.0.0.1") (Just "53")
  withUDPSocket addrinfos $ \dat sender -> do
    putStrLn $ prettyHex dat
    let msg = runGet runBinGet $ BSL.fromStrict dat

    let answers = map (zoneLookup testZone . questionName) $ questions msg

    let hdr' = (header msg) { queryResponse = Response
                            , answerRecordCount = fromIntegral $ length answers
                            , responseCode = RCNoError
                            }
    let resmsg = msg {header = hdr', answers = answers}
    let res = runPut $ runBinPut resmsg
    pPrint msg
    sender $ BSL.toStrict res
    pPrint resmsg
    putStrLn $ prettyHex $ BSL.toStrict res

