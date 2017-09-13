{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
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

import           Control.Monad         (forM_, replicateM)
import           Control.Monad.Loops   (whileJust)
import qualified Data.Binary.Bits.Get  as Bits
import qualified Data.Binary.Bits.Put  as Bits
import qualified Data.Binary.Get as Bin
import qualified Data.ByteString.Char8 as BS
import           Data.Word             (Word16, Word32)
import           Protolude

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

-- | Specifies kind of query in this message. This value is set by the originator of a query and copied into
--   the response.
data OpCode
  = OpQuery   -- ^ RFC1035
  | OpIQuery  -- ^ RFC3425
  | OpStatus  -- ^ RFC1035
  | OpNotify  -- ^ RFC1996
  | OpUpdate  -- ^ RFC2136
  deriving (Eq, Ord, Show)

instance BinaryPut OpCode where
  bput x = Bits.putWord8 4 $ case x of
    OpQuery  -> 0
    OpIQuery -> 1
    OpStatus -> 2
    OpNotify -> 4
    OpUpdate -> 5

instance BinaryGet OpCode where
  bget = do
    op <- Bits.getWord8 4
    return $ case op of
      0 -> OpQuery
      1 -> OpIQuery
      2 -> OpStatus
      4 -> OpNotify
      5 -> OpUpdate
      _ -> panic $ "Unknown opcode received " <> show op

instance BinaryBit OpCode

-- | Response code - this 4 bit field is set as part of responses.
data RCode
  = RCNoError     -- ^ No Error                           (RFC1035)
  | RCFormErr     -- ^ Format Error                       (RFC1035)
  | RCServFail    -- ^ Server Failure                     (RFC1035)
  | RCNXDomain    -- ^ Non-Existent Domain                (RFC1035)
  | RCNotImp      -- ^ Not Implemented                    (RFC1035)
  | RCRefused     -- ^ Query Refused                      (RFC1035)
  | RCYXDomain    -- ^ Name Exists when it should not	    (RFC2136, RFC6672)
  | RCYXRRSet     -- ^ RR Set Exists when it should not	  (RFC2136)
  | RCNXRRSet     -- ^ RR Set that should exist does not	(RFC2136)
  | RCNotAuth     -- ^ Not Authorized	                    (RFC2845)
  | RCNotZone     -- ^ Name not contained in zone	        (RFC2136)
  | RCBadSig      -- ^ TSIG Signature Failure	            (RFC2845)
  | RCBadKey      -- ^ Key not recognized	                (RFC2845)
  | RCBadTime     -- ^ Signature out of time window	      (RFC2845)
  | RCBadMode     -- ^ Bad TKEY Mode	                    (RFC2930)
  | RCBadName     -- ^ Duplicate key name	                (RFC2930)
  | RCBadAlg      -- ^ Algorithm not supported	          (RFC2930)
  | RCBadTrunc    -- ^ Bad Truncation	                    (RFC4635)
  | RCBadCookie   -- ^ Bad/missing Server Cookie	        (RFC7873)
  deriving (Eq, Ord, Show)

instance BinaryPut RCode where
  bput x = Bits.putWord8 4 $ case x of
    RCNoError   -> 0
    RCFormErr   -> 1
    RCServFail  -> 2
    RCNXDomain  -> 3
    RCNotImp    -> 4
    RCRefused   -> 5
    RCYXDomain  -> 6
    RCYXRRSet   -> 7
    RCNXRRSet   -> 8
    RCNotAuth   -> 9
    RCNotZone   -> 10
    RCBadSig    -> 16
    RCBadKey    -> 17
    RCBadTime   -> 18
    RCBadMode   -> 19
    RCBadName   -> 20
    RCBadAlg    -> 21
    RCBadTrunc  -> 22
    RCBadCookie -> 23

instance BinaryGet RCode where
  bget = do
    code <- Bits.getWord8 4
    return $ case code of
      0  -> RCNoError
      1  -> RCFormErr
      2  -> RCServFail
      3  -> RCNXDomain
      4  -> RCNotImp
      5  -> RCRefused
      6  -> RCYXDomain
      7  -> RCYXRRSet
      8  -> RCNXRRSet
      9  -> RCNotAuth
      10 -> RCNotZone
      16 -> RCBadSig
      17 -> RCBadKey
      18 -> RCBadTime
      19 -> RCBadMode
      20 -> RCBadName
      21 -> RCBadAlg
      22 -> RCBadTrunc
      23 -> RCBadCookie
      _  -> panic $ "Unknown RCode received " <> show code

-- | There are three subcategories of 'ResourceRecordType' numbers: data TYPEs, QTYPEs, and Meta-TYPEs.
--
--   Data TYPEs are the means of storing data.  QTYPES can only be used in queries. Meta-TYPEs designate
--   transient data associated with a particular DNS message and, in some cases, can also be used in
--   queries. Thus far, data TYPEs have been assigned from 1 upward, plus the block from 100 through 103,
--   and from 32,768 upward, while Q and Meta-TYPEs have been assigned from 255 downward except for the OPT
--   Meta-RR, which is assigned TYPE 41.
data ResourceRecordType
  = RRA          -- ^ a host address                         (RFC1035)
  | RRNS         -- ^ an authoritative name server           (RFC1035)
  | RRMD         -- ^ a mail destination (OBSELETE)          (RFC1035)
  | RRMF         -- ^ a mail forwarder   (OBSELETE)          (RFC1035)
  | RRCNAME      -- ^ the canonical name for an alias        (RFC1035)
  | RRSOA        -- ^ marks the start of a zone of authority (RFC1035)
  | RRMB         -- ^ a mailbox domain name                  (RFC1035)
  | RRMG         -- ^ a mail group member                    (RFC1035)
  | RRMR         -- ^ a mail rename domain name              (RFC1035)
  | RRNULL       -- ^ a null RR                              (RFC1035)
  | RRWKS        -- ^ a well known service description       (RFC1035)
  | RRPTR        -- ^ a domain name pointer                  (RFC1035)
  | RRHINFO      -- ^ host information                       (RFC1035)
  | RRMINFO      -- ^ mailbox or mail list information       (RFC1035)
  | RRMX         -- ^ mail exchange                          (RFC1035)
  | RRTXT        -- ^ text strings	                         (RFC1035)
  | RRRP         -- ^ for Responsible Person	               (RFC1183)
  | RRAFSDB      -- ^ for AFS Data Base location	           (RFC1183, RFC5864)
  | RRX25        -- ^ for X.25 PSDN address	                 (RFC1183)
  | RRISDN       -- ^ for ISDN address	                     (RFC1183)
  | RRRT         -- ^ for Route Through	                     (RFC1183)
  | RRNSAP       -- ^ for NSAP address, NSAP style A record  (RFC1706)
  | RRNSAP_PTR   -- ^ for domain name pointer, NSAP style	   (RFC1348, RFC1637, RFC1706)
  | RRSIG        -- ^ for security signature	               (RFC4034, RFC3755, RFC2535, RFC2536, RFC2537, RFC2931, RFC3110, RFC3008)
  | RRKEY        -- ^ for security key	                     (RFC4034, RFC3755, RFC2535, RFC2536, RFC2537, RFC2539, RFC3008, RFC3110)
  | RRPX         -- ^ X.400 mail mapping information	       (RFC2163)
  | RRGPOS       -- ^ Geographical Position	                 (RFC1712)
  | RRAAAA       -- ^ IP6 Address	                           (RFC3596)
  | RRLOC        -- ^ Location Information	                 (RFC1876)
  | RRNXT        -- ^ Next Domain (OBSOLETE)	               (RFC3755, RFC2535)
  | RREID        -- ^ Endpoint Identifier	                   (http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt)
  | RRNIMLOC     -- ^ Nimrod Locator	                       (http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt)
  | RRSRV        -- ^ Server Selection	                     (RFC2782)
  | RRATMA       -- ^ ATM Address	                           (ATM Forum Technical Committee, "ATM Name System, V2.0")
  | RRNAPTR      -- ^ Naming Authority Pointer	             (RFC2915, RFC2168, RFC3403)
  | RRKX         -- ^ Key Exchanger	                         (RFC2230)
  | RRCERT       -- ^ CERT	                                 (RFC4398)
  | RRA6         -- ^ A6 (OBSOLETE - use AAAA)	             (RFC3226, RFC2874, RFC6563)
  | RRDNAME      -- ^ DNAME	                                 (RFC6672)
  | RRSINK       -- ^ SINK	                                 (http://tools.ietf.org/html/draft-eastlake-kitchen-sink)
  | RROPT        -- ^ OPT	                                   (RFC6891, RFC3225)
  | RRAPL        -- ^ APL	                                   (RFC3123)
  | RRDS         -- ^ Delegation Signer	                     (RFC4034, RFC3658)
  | RRSSHFP      -- ^ SSH Key Fingerprint	                   (RFC4255)
  | RRIPSECKEY   -- ^ IPSECKEY	                             (RFC4025)
  | RRRRSIG      -- ^ RRSIG	                                 (RFC4034, RFC3755)
  | RRNSEC       -- ^ NSEC	                                 (RFC4034, RFC3755)
  | RRDNSKEY     -- ^ DNSKEY	                               (RFC4034, RFC3755)
  | RRDHCID      -- ^ DHCID	                                 (RFC4701)
  | RRNSEC3      -- ^ NSEC3	                                 (RFC5155)
  | RRNSEC3PARAM -- ^ NSEC3PARAM	                           (RFC5155)
  | RRTLSA       -- ^ TLSA	                                 (RFC6698)
  | RRSMIMEA     -- ^ S/MIME cert association	               (RFC8162)
  | RRHIP        -- ^ Host Identity Protocol	               (RFC8005)
  | RRNINFO      -- ^ NINFO	                                 (Jim_Reid)
  | RRRKEY       -- ^ RKEY	                                 (Jim_Reid)
  | RRTALINK     -- ^ Trust Anchor LINK	                     (Wouter_Wijngaards)
  | RRCDS        -- ^ Child DS	                             (RFC7344)
  | RRCDNSKEY    -- ^ DNSKEY the Child wants reflected in DS (RFC7344)
  | RROPENPGPKEY -- ^ OpenPGP Key	                           (RFC7929)
  | RRCSYNC      -- ^ Child-To-Parent Synchronization	       (RFC7477)
  | RRSPF        -- ^                                        (RFC7208)
  | RRUINFO      -- ^                                        (IANA-Reserved)
  | RRUID        -- ^                                        (IANA-Reserved)
  | RRGID        -- ^                                        (IANA-Reserved)
  | RRUNSPEC     -- ^                                        (IANA-Reserved)
  | RRNID        -- ^                                        (RFC6742)
  | RRL32        -- ^                                        (RFC6742)
  | RRL64        -- ^                                        (RFC6742)
  | RRLP         -- ^                                        (RFC6742)
  | RREUI48      -- ^ an EUI-48 address	                     (RFC7043)
  | RREUI64      -- ^ an EUI-64 address	                     (RFC7043)
  | RRTKEY       -- ^ Transaction Key	                       (RFC2930)
  | RRTSIG       -- ^ Transaction Signature	                 (RFC2845)
  | RRIXFR       -- ^ incremental transfer	                 (RFC1995)
  | RRAXFR       -- ^ transfer of an entire zone	           (RFC1035, RFC5936)
  | RRMAILB      -- ^ mailbox-related RRs (MB, MG or MR)	   (RFC1035)
  | RRMAILA      -- ^ mail agent RRs (OBSOLETE - see MX)	   (RFC1035)
  | RRWILDCARD   -- ^ A request for all records the server/cache has available (RFC1035, RFC6895)
  | RRURI        -- ^ URI	[RFC7553]
  | RRCAA        -- ^ Certification Authority Restriction	   (RFC6844)
  | RRAVC        -- ^ Application Visibility and Control	   (Wolfgang_Riedel)
  | RRDOA        -- ^ Digital Object Architecture	           (draft-durand-doa-over-dns)
  | RRTA         -- ^ DNSSEC Trust Authorities	             (Sam_Weiler)
  | RRDLV        -- ^ DNSSEC Lookaside Validation	           (RFC4431)
  deriving (Eq, Ord, Show)

instance BinaryPut ResourceRecordType where
  bput x = Bits.putWord16be 16 $ case x of
    RRA          -> 1
    RRNS         -> 2
    RRMD         -> 3
    RRMF         -> 4
    RRCNAME      -> 5
    RRSOA        -> 6
    RRMB         -> 7
    RRMG         -> 8
    RRMR         -> 9
    RRNULL       -> 10
    RRWKS        -> 11
    RRPTR        -> 12
    RRHINFO      -> 13
    RRMINFO      -> 14
    RRMX         -> 15
    RRTXT        -> 16
    RRRP         -> 17
    RRAFSDB      -> 18
    RRX25        -> 19
    RRISDN       -> 20
    RRRT         -> 21
    RRNSAP       -> 22
    RRNSAP_PTR   -> 23
    RRSIG        -> 24
    RRKEY        -> 25
    RRPX         -> 26
    RRGPOS       -> 27
    RRAAAA       -> 28
    RRLOC        -> 29
    RRNXT        -> 30
    RREID        -> 31
    RRNIMLOC     -> 32
    RRSRV        -> 33
    RRATMA       -> 34
    RRNAPTR      -> 35
    RRKX         -> 36
    RRCERT       -> 37
    RRA6         -> 38
    RRDNAME      -> 39
    RRSINK       -> 40
    RROPT        -> 41
    RRAPL        -> 42
    RRDS         -> 43
    RRSSHFP      -> 44
    RRIPSECKEY   -> 45
    RRRRSIG      -> 46
    RRNSEC       -> 47
    RRDNSKEY     -> 48
    RRDHCID      -> 49
    RRNSEC3      -> 50
    RRNSEC3PARAM -> 51
    RRTLSA       -> 52
    RRSMIMEA     -> 53
    RRHIP        -> 55
    RRNINFO      -> 56
    RRRKEY       -> 57
    RRTALINK     -> 58
    RRCDS        -> 59
    RRCDNSKEY    -> 60
    RROPENPGPKEY -> 61
    RRCSYNC      -> 62
    RRSPF        -> 99
    RRUINFO      -> 100
    RRUID        -> 101
    RRGID        -> 102
    RRUNSPEC     -> 103
    RRNID        -> 104
    RRL32        -> 105
    RRL64        -> 106
    RRLP         -> 107
    RREUI48      -> 108
    RREUI64      -> 109
    RRTKEY       -> 249
    RRTSIG       -> 250
    RRIXFR       -> 251
    RRAXFR       -> 252
    RRMAILB      -> 253
    RRMAILA      -> 254
    RRWILDCARD   -> 255
    RRURI        -> 256
    RRCAA        -> 257
    RRAVC        -> 258
    RRDOA        -> 259
    RRTA         -> 32768
    RRDLV        -> 32769

instance BinaryGet ResourceRecordType where
  bget = do
    rrt <- Bits.getWord16be 16
    return $ case rrt of
      1     -> RRA
      2     -> RRNS
      3     -> RRMD
      4     -> RRMF
      5     -> RRCNAME
      6     -> RRSOA
      7     -> RRMB
      8     -> RRMG
      9     -> RRMR
      10    -> RRNULL
      11    -> RRWKS
      12    -> RRPTR
      13    -> RRHINFO
      14    -> RRMINFO
      15    -> RRMX
      16    -> RRTXT
      17    -> RRRP
      18    -> RRAFSDB
      19    -> RRX25
      20    -> RRISDN
      21    -> RRRT
      22    -> RRNSAP
      23    -> RRNSAP_PTR
      24    -> RRSIG
      25    -> RRKEY
      26    -> RRPX
      27    -> RRGPOS
      28    -> RRAAAA
      29    -> RRLOC
      30    -> RRNXT
      31    -> RREID
      32    -> RRNIMLOC
      33    -> RRSRV
      34    -> RRATMA
      35    -> RRNAPTR
      36    -> RRKX
      37    -> RRCERT
      38    -> RRA6
      39    -> RRDNAME
      40    -> RRSINK
      41    -> RROPT
      42    -> RRAPL
      43    -> RRDS
      44    -> RRSSHFP
      45    -> RRIPSECKEY
      46    -> RRRRSIG
      47    -> RRNSEC
      48    -> RRDNSKEY
      49    -> RRDHCID
      50    -> RRNSEC3
      51    -> RRNSEC3PARAM
      52    -> RRTLSA
      53    -> RRSMIMEA
      55    -> RRHIP
      56    -> RRNINFO
      57    -> RRRKEY
      58    -> RRTALINK
      59    -> RRCDS
      60    -> RRCDNSKEY
      61    -> RROPENPGPKEY
      62    -> RRCSYNC
      99    -> RRSPF
      100   -> RRUINFO
      101   -> RRUID
      102   -> RRGID
      103   -> RRUNSPEC
      104   -> RRNID
      105   -> RRL32
      106   -> RRL64
      107   -> RRLP
      108   -> RREUI48
      109   -> RREUI64
      249   -> RRTKEY
      250   -> RRTSIG
      251   -> RRIXFR
      252   -> RRAXFR
      253   -> RRMAILB
      254   -> RRMAILA
      255   -> RRWILDCARD
      256   -> RRURI
      257   -> RRCAA
      258   -> RRAVC
      259   -> RRDOA
      32768 -> RRTA
      32769 -> RRDLV
      _     -> panic $ "Unknown record resource type received " <> show rrt

instance BinaryBit ResourceRecordType

-- | 'DNSClass'es have been little used but constitute another dimension of the DNS distributed database.
--   In particular, there is no necessary relationship between the namespace or root servers for one data 'DNSClass'
--   and those for another data 'DNSClass'.  The same 'DNSName' can have completely different meanings in different CLASSes.
data DNSClass = ClsInternet -- ^ RFC1035
              | ClsChaos    -- ^ D. Moon, "Chaosnet", A.I. Memo 628, June 1981.
              | ClsHesiod   -- ^ Project Athena Technical Plan - Name Service, April 1987
              | ClsNone     -- ^ RFC2136
              | ClsAny      -- ^ RFC1035
              deriving (Eq, Ord, Show)

instance BinaryPut DNSClass where
  bput x = Bits.putWord16be 16 $ case x of
    ClsInternet -> 0x0001
    ClsChaos    -> 0x0003
    ClsHesiod   -> 0x0004
    ClsNone     -> 0x00FE
    ClsAny      -> 0x00FF

instance BinaryGet DNSClass where
  bget = do
    cls <- Bits.getWord16be 16
    return $ case cls of
      0x0001 -> ClsInternet
      0x0003 -> ClsChaos
      0x0004 -> ClsHesiod
      0x00FE -> ClsNone
      0x00FF -> ClsAny
      _      -> panic $ "Unknown dns class received " <> show cls

instance BinaryBit DNSClass

-- | Labels must follow the rules for ARPANET host names. They must start with a letter, end with a letter or digit,
--   and have as interior characters only letters, digits, and hyphen.  There are also some restrictions on the length.
--   Labels must be 63 characters or less.
--
--   Each label is represented as a one octet length field followed by that number of octets. Since every domain name
--   ends with the null label of the root, a domain name is terminated by a length byte of zero.
newtype DNSLabel = DNSLabel BS.ByteString deriving (Eq, Ord, Show)

instance BinaryPut DNSLabel where
  bput (DNSLabel l) = do
    let len = BS.length l
    Bits.putWord8 8 (fromIntegral len)
    Bits.putByteString l

instance BinaryGet DNSLabel where
  bget = do
    len <- Bits.getWord8 8
    case len of
      0x00 -> return $ DNSLabel BS.empty
      _    -> DNSLabel <$> Bits.getByteString (fromIntegral len)

instance BinaryBit DNSLabel

-- | Is it the end of a set of labels (0x00)
nullLabel :: DNSLabel -> Bool
nullLabel (DNSLabel x) = BS.null x

-- | Make a 'DNSLabel' from a 'String'
mkLabelFromStr :: Text -> DNSLabel
mkLabelFromStr s = DNSLabel $ toS s

instance BinarySize DNSLabel where
  byteSz (DNSLabel l) = BS.length l + 1

-- | 'DNSName' is an owner name, i.e., the name of the node to which this resource record pertains. 'DNSName's are
--   specific to a 'DNSClass'.  'DNSName's consist of an ordered sequence of one or more 'DNSLabel's.
newtype DNSName = DNSName { nameComponents :: [DNSLabel] } deriving (Show, Eq, Ord)

-- | Make a 'DNSName' given a dotted form name eg, "ashleytowns.id.au"
mkDNSNameFromStr :: Text -> DNSName
mkDNSNameFromStr str = DNSName $ map DNSLabel $ BS.split '.' $ toS str

instance BinaryPut DNSName where
  bput (DNSName x) = do
    forM_ x bput
    Bits.putWord8 8 0x00

instance BinaryGet DNSName where
  bget = DNSName <$> whileJust readLabel return
    where
      readLabel :: Bits.BitGet (Maybe DNSLabel)
      readLabel = do
        label <- bget
        return $ if nullLabel label then Nothing else Just label

instance BinaryBit DNSName

instance BinarySize DNSName where
  byteSz (DNSName els) = fromIntegral $ foldl (\acc e -> acc + byteSz e) 1 els

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

-- | A variable length string that describes the resource. The format of this information varies according to the
--   'ResourceRecordType' and 'DNSClass' of the resource record
data RData
  -- | A records cause no additional section processing. The 'rrData' section of an A line in a master
  --   file is an Internet address expressed as four decimal numbers separated by dots without any imbedded spaces
  = RDA Word32
  -- | A 'DNSName' which specifies the canonical or primary name for the owner. The owner name is an alias
  | RDCName DNSName
  -- | HINFO records are used to acquire general information about a host. The main use is for protocols such as
  --   FTP that can use special procedures when talking between machines or operating systems of the same type.
  | RDHInfo DNSLabel DNSLabel
  -- | MX records cause type A additional section processing for the host specified by EXCHANGE. The use of
  --   MX RRs is explained in detail in (RFC974)
  | RDMX Word16 DNSName
  | RDSOA DNSName DNSName Word32 Word32 Word32 Word32 Word32
  | RDOpt Word16 Word16 [Word8]
  deriving (Eq, Ord, Show)

instance BinaryPut RData where
  bput (RDA a)      = Bits.putWord32be 32 a
  bput (RDCName cn) = bput cn
  bput (RDHInfo cpu os) = do
    bput cpu
    bput os
  bput (RDMX pref xchg) = do
    Bits.putWord16be 16 pref
    bput xchg
  bput (RDSOA mname rname serial refresh retry expire minm) = do
    bput mname
    bput rname
    Bits.putWord32be 32 serial
    Bits.putWord32be 32 refresh
    Bits.putWord32be 32 retry
    Bits.putWord32be 32 expire
    Bits.putWord32be 32 minm
  bput (RDOpt code len octs) = do
    Bits.putWord16be 16 code
    Bits.putWord16be 16 len
    forM_ octs $ Bits.putWord8 8

-- | Treat stream as a specific 'RData' given a 'ResourceRecordType'
getRData :: ResourceRecordType -> Bits.BitGet RData
getRData typ =
  case typ of
    RRA     -> RDA <$> Bits.getWord32be 32
    RRCNAME -> RDCName <$> bget
    RRHINFO -> RDHInfo <$> bget <*> bget
    RRMX    -> do
      pref <- Bits.getWord16be 16
      xchg <- bget
      return $ RDMX pref xchg
    RRSOA   -> do
      mname <- bget
      rname <- bget
      serial <- Bits.getWord32be 32
      refresh <- Bits.getWord32be 32
      retry <- Bits.getWord32be 32
      expire <- Bits.getWord32be 32
      minm <- Bits.getWord32be 32
      return $ RDSOA mname rname serial refresh retry expire minm
    RROPT    -> do
      code <- Bits.getWord16be 16
      len <- Bits.getWord16be 16
      octs <- replicateM (fromIntegral len) $ Bits.getWord8 8
      return $ RDOpt code len octs
    _    -> panic $ "Unsupported RDATA type " <> show typ

instance BinarySize RData where
  byteSz (RDA _)                       = 4
  byteSz (RDCName name)                = byteSz name
  byteSz (RDHInfo os cpu)              = byteSz os + byteSz cpu
  byteSz (RDMX _ chg)                  = 2 + byteSz chg
  byteSz (RDSOA mname rname _ _ _ _ _) = 20 + byteSz mname + byteSz rname

-- | The answer, authority, and additional sections all share the same format: a variable number of resource records,
--   where the number of records is specified in the corresponding count field in the header.
data StdResourceRecord = StdResourceRecord
  { rrName   :: DNSName            -- ^ a domain name to which this resource record pertains.
  , rrType   :: ResourceRecordType -- ^ this field specifies the meaning of the data in the 'rrData' field.
  , rrClass  :: DNSClass           -- ^ specifies the class of the data in the 'rrData' field.
  , rrTTL    :: Word32             -- ^ specifies the time interval (in seconds) that the resource record may
                                   --   be cached before it should be discarded.
  , rrLength :: Word16             -- ^ specifies the length in octets of the 'rrData' field.
  , rrData   :: RData              -- ^ a variable length string that describes the resource.
  } deriving (Eq, Ord, Show)

instance BinaryGet StdResourceRecord where
  bget = do
    labels <- bget
    typ <- bget
    cls <- bget
    ttl <- Bits.getWord32be 32
    len <- Bits.getWord16be 16
    dat <- getRData typ
    return StdResourceRecord { rrName = labels
                          , rrType = typ
                          , rrClass = cls
                          , rrTTL = ttl
                          , rrLength = len
                          , rrData = dat
                          }

instance BinaryPut StdResourceRecord where
  bput StdResourceRecord {..} = do
    bput rrName
    bput rrType
    bput rrClass
    Bits.putWord32be 32 rrTTL
    Bits.putWord16be 16 rrLength
    bput rrData

instance BinaryBit StdResourceRecord

-- | Calculate the 'rrLength' field of a 'StdResourceRecord'
calculateRRLength :: StdResourceRecord -> StdResourceRecord
calculateRRLength rr = rr {rrLength = fromIntegral . byteSz $ rrData rr}

data OptResourceRecord = OptResourceRecord
  { rrOptName          :: DNSName
  , rrOptType          :: ResourceRecordType
  , rrOptPayloadSz     :: Word16
  , rrOptExtendedRCode :: Word32
  , rrOptLength        :: Word16
  , rrOptData          :: RData
  } deriving (Eq, Ord, Show)

instance BinaryGet OptResourceRecord where
  bget = do
    labels <- bget
    typ <- bget
    paysz <- Bits.getWord16be 16
    extrc <- Bits.getWord32be 32
    len <- Bits.getWord16be 16
    dat <- getRData typ
    return OptResourceRecord { rrOptName = labels
                             , rrOptType = typ
                             , rrOptPayloadSz = paysz
                             , rrOptExtendedRCode = extrc
                             , rrOptLength = len
                             , rrOptData = dat
                             }

instance BinaryPut OptResourceRecord where
  bput OptResourceRecord {..} = do
    bput rrOptName
    bput rrOptType
    Bits.putWord16be 16 rrOptPayloadSz
    Bits.putWord32be 32 rrOptExtendedRCode
    Bits.putWord16be 16 rrOptLength
    bput rrOptData

instance BinaryBit OptResourceRecord

data ResourceRecord = Std StdResourceRecord
                    | Opt OptResourceRecord
                    deriving (Eq, Ord, Show)

instance BinaryGet ResourceRecord where
  bget = do
    -- Look ahead for BitGet would be nicee :(
    name <- bget
    typ <- bget
    case typ of
      RROPT -> do
        paysz <- Bits.getWord16be 16
        extrc <- Bits.getWord32be 32
        len <- Bits.getWord16be 16
        dat <- getRData typ
        return $ Opt OptResourceRecord { rrOptName = name
                                       , rrOptType = typ
                                       , rrOptPayloadSz = paysz
                                       , rrOptExtendedRCode = extrc
                                       , rrOptLength = len
                                       , rrOptData = dat
                                       }
      _ -> do
        cls <- bget
        ttl <- Bits.getWord32be 32
        len <- Bits.getWord16be 16
        dat <- getRData typ
        return $ Std StdResourceRecord { rrName = name
                                       , rrType = typ
                                       , rrClass = cls
                                       , rrTTL = ttl
                                       , rrLength = len
                                       , rrData = dat
                                       }

instance BinaryPut ResourceRecord where
  bput (Std x) = bput x
  bput (Opt x) = bput x

instance BinaryBit ResourceRecord
