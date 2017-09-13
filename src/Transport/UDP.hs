module Transport.UDP where

import           Control.Monad             (forever)
import qualified Data.ByteString           as BS
import           Network.Socket            hiding (recv, recvFrom, send, sendTo)
import           Network.Socket.ByteString
import           Protolude

type Sender = (BS.ByteString -> IO ())

withUDPSocket :: AddrInfo -> (BS.ByteString -> Sender -> IO ()) -> IO ()
withUDPSocket addr f = do
  sock <- socket (addrFamily addr) Datagram defaultProtocol
  bind sock (addrAddress addr)
  forever $ do
    (dat, clientAddr) <- recvFrom sock 4096
    let sender res = sendAllTo sock res clientAddr
    f dat sender
