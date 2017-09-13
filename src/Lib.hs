module Lib
    ( someFunc
    ) where

import           DNS.Transport
import           Protolude

someFunc :: IO ()
someFunc = server
