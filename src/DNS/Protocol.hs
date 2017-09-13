{-# LANGUAGE RecordWildCards #-}
{-|
Module      : DNS.Protocol
Description : Deals with serialising/deserialing DNS protocol packets.
License     : MIT
Maintainer  : mail@ashleytowns.id.au
Stability   : experimental
Portability : POSIX

The domain system is a mixture of functions and data types which are an official protocol and functions and data types
which are still experimental. Since the domain system is intentionally extensible, new data types and experimental
behavior should always be expected in parts of the system beyond the official protocol. The official protocol parts
include standard queries, responses and the Internet class RR data formats (e.g., host addresses).

The goal is to fully support RFC1035, partially supports

RFC1183, RFC1348, RFC1637, RFC1706, RFC1712, RFC1876, RFC1995, RFC1996, RFC2136, RFC2163, RFC2168, RFC2230,
RFC2535, RFC2536, RFC2537, RFC2539, RFC2782, RFC2845, RFC2874, RFC2915, RFC2930, RFC2931, RFC3008, RFC3110,
RFC3123, RFC3225, RFC3226, RFC3403, RFC3425, RFC3596, RFC3658, RFC3755, RFC4025, RFC4034, RFC4255, RFC4398,
RFC4431, RFC4635, RFC4701, RFC5155, RFC5864, RFC5936, RFC6563, RFC6672, RFC6698, RFC6742, RFC6844, RFC6891,
RFC6895, RFC7043, RFC7208, RFC7344, RFC7477, RFC7553, RFC7873, RFC7929, RFC8005, RFC8162, RFC974

at the protocol level.
-}
module DNS.Protocol where

import           Control.Monad                   (forM_, replicateM)
import qualified Data.Binary.Bits.Get            as Bits
import qualified Data.Binary.Bits.Put            as Bits
import           Data.Word                       (Word16)
import           Protolude

import           DNS.Protocol.DNSClass
import           DNS.Protocol.DNSName
import           DNS.Protocol.DNSOpcode
import           DNS.Protocol.ResourceRecord
import           DNS.Protocol.ResourceRecordType
import           DNS.Protocol.ResponseCode

import           Parsing.BinaryBit

-- | All communications inside of the domain protocol are carried in a single
--   format called a message.  The top level format of message is divided
--   into 5 sections (some of which are empty in certain cases) shown below:
--
--   @
--      +---------------------+
--      |        Header       |
--      +---------------------+
--      |       Question      | the question for the name server
--      +---------------------+
--      |        Answer       | RRs answering the question
--      +---------------------+
--      |      Authority      | RRs pointing toward an authority
--      +---------------------+
--      |      Additional     | RRs holding additional information
--      +---------------------+
--   @
--
--   The header section is always present.  The header includes fields that
--   specify which of the remaining sections are present, and also specify
--   whether the message is a query or a response, a standard query or some
--   other opcode, etc.
data DNSMessage = DNSMessage
  { header     :: MessageHeader    -- ^ the header for this 'DNSMessage'
  , questions  :: [Question]       -- ^ the 'Question' for the nameserver.
  , answers    :: [ResourceRecord] -- ^ 'ResourceRecord's answering the 'Question'.
  , authority  :: [ResourceRecord] -- ^ 'ResourceRecord's pointing toward an authority.
  , additional :: [ResourceRecord] -- ^ 'ResourceRecord's holding additional information.
  } deriving (Eq, Ord, Show)

instance BinaryGet DNSMessage where
  bget = do
    hdr <- bget
    qs <- replicateM (fromIntegral $ questionCount hdr) bget
    as <- replicateM (fromIntegral $ answerRecordCount hdr) bget
    aus <- replicateM (fromIntegral $ authorityRecordCount hdr) bget
    ads <- replicateM (fromIntegral $ additionalRecordCount hdr) bget
    return DNSMessage { header = hdr
                      , questions = qs
                      , answers = as
                      , authority = aus
                      , additional = ads
                      }

instance BinaryPut DNSMessage where
  bput DNSMessage {..} = do
    bput header
    forM_ questions bput
    forM_ answers bput
    forM_ authority bput
    forM_ additional bput

instance BinaryBit DNSMessage

-- | The header section is always present.  The header includes fields that specify which of the remaining
--   sections are present, and also specify whether the message is a query or a response, a standard query
--   or some other opcode, etc.
data MessageHeader = MessageHeader
  { -- | this identifier is copied the corresponding reply and can be used by the requester to match up replies to
    --   outstanding queries.
    identifier            :: Word16
    -- | specifies whether this message is a query, or a response
  , queryResponse         :: QueryResponse
    -- | specifies kind of query in this message.  This value is set by the originator
    --   of a query and copied into the response
  , opcode                :: OpCode
    -- | this is valid in responses, and specifies that the responding name server is an authority for the domain name
    --   in question section
  , authoritive           :: Bool
    -- | specifies that this message was truncated due to length greater than that permitted on the transmission channel
  , truncated             :: Bool
    -- | this may be set in a query and is copied into the response. If recursionDesired is set, it directs
    --   the name server to pursue the query recursively
  , recursionDesired      :: Bool
    -- | denotes whether recursive query support is available in the name server
  , recursionAvailable    :: Bool
    -- | is set as part of responses
  , responseCode          :: RCode
    -- | specifies the number of entries in the question section
  , questionCount         :: Word16
    -- | specifies the number of resource records in the answer section
  , answerRecordCount     :: Word16
    -- | specifies the number of name server resource records in the authority records section
  , authorityRecordCount  :: Word16
    -- | specifies the number of resource records in the additional records section
  , additionalRecordCount :: Word16
  } deriving (Eq, Ord, Show)

instance BinaryGet MessageHeader where
  bget = do
    ident <- Bits.getWord16be 16
    qr <- bget
    op <- bget
    auth <- Bits.getBool
    trunc <- Bits.getBool
    recurDes <- Bits.getBool
    recurAvail <- Bits.getBool
    _skip <- Bits.getWord8 3
    resp <- bget
    qc <- Bits.getWord16be 16
    arc <- Bits.getWord16be 16
    aurc <- Bits.getWord16be 16
    adrc <- Bits.getWord16be 16
    return
      MessageHeader
      { identifier = ident
      , queryResponse = qr
      , opcode = op
      , authoritive = auth
      , truncated = trunc
      , recursionDesired = recurDes
      , recursionAvailable = recurAvail
      , responseCode = resp
      , questionCount = qc
      , answerRecordCount = arc
      , authorityRecordCount = aurc
      , additionalRecordCount = adrc
      }

instance BinaryPut MessageHeader where
  bput MessageHeader {..} = do
    Bits.putWord16be 16 identifier
    bput queryResponse
    bput opcode
    Bits.putBool authoritive
    Bits.putBool truncated
    Bits.putBool recursionDesired
    Bits.putBool recursionAvailable
    Bits.putWord8 3 0
    bput responseCode
    Bits.putWord16be 16 questionCount
    Bits.putWord16be 16 answerRecordCount
    Bits.putWord16be 16 authorityRecordCount
    Bits.putWord16be 16 additionalRecordCount

instance BinaryBit MessageHeader

-- | Specifies whether this message is a query, or a response.
data QueryResponse
  = Query
  | Response
  deriving (Eq, Ord, Show)

instance BinaryPut QueryResponse where
  bput Query    = Bits.putBool False
  bput Response = Bits.putBool True

instance BinaryGet QueryResponse where
  bget = do
    b <- Bits.getBool
    return
      (if b
         then Response
         else Query)

instance BinaryBit QueryResponse

-- | The question section is used to carry the "question" in most queries, i.e., the parameters that define what is
--   being asked.  The section contains usually 1 entries,
data Question = Question
  { questionName  :: DNSName            -- ^ a domain name represented as a sequence of labels
  , questionType  :: ResourceRecordType -- ^ specifies the type of the query.
  , questionClass :: DNSClass           -- ^ specifies the class of the query.
  } deriving (Eq, Ord, Show)

instance BinaryGet Question where
  bget = do
    name <- bget
    typ <- bget
    cls <- bget
    return Question {questionName = name, questionType = typ, questionClass = cls}

instance BinaryPut Question where
  bput Question {..} = do
    bput questionName
    bput questionType
    bput questionClass

instance BinaryBit Question

