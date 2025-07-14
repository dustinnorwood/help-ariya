{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Base16 as B16
import Data.Maybe (fromMaybe)
import qualified Crypto.KDF.Scrypt as Scrypt
import Crypto.Saltine.Class (decode)
import Crypto.Saltine.Core.SecretBox as SB
import System.Environment (getArgs)

-- Derive a SecretBox key using a password and a salt
deriveKey :: BS.ByteString -> BS.ByteString -> Key
deriveKey password salt =
  let scryptParams = Scrypt.Parameters
        { Scrypt.n = 16384
        , Scrypt.r = 8
        , Scrypt.p = 1
        , Scrypt.outputLength = 32
        }
   in fromMaybe (error "could not decode encryption key") . decode $
        Scrypt.generate scryptParams password salt

-- Hex decode with validation
decodeHex :: String -> BS.ByteString
decodeHex s =
  let bs = B16.decode (C8.pack s)
  in case bs of
       Right bs' -> bs'
       Left s' ->  error $ "Invalid hex input" ++ s'

-- Convert ByteString to hex-encoded string
encodeHex :: BS.ByteString -> String
encodeHex = C8.unpack . B16.encode

main :: IO ()
main = do
  args <- getArgs
  case args of
    [saltHex, nonceHex, cipherHex, pw] -> do
      let salt     = decodeHex saltHex
          nonceBs  = decodeHex nonceHex
          cipherBs = decodeHex cipherHex
          password = C8.pack pw

      -- Convert nonce
      nonce <- case decode nonceBs :: Maybe Nonce of
        Just n  -> return n
        Nothing -> error "Invalid nonce"

      -- Derive key
      let key = deriveKey password salt

      -- Decrypt
      case SB.secretboxOpen key nonce cipherBs of
        Just plaintext -> putStrLn $ encodeHex plaintext
        Nothing        -> error "Decryption failed"
    _ -> putStrLn "Usage: program <hexSalt> <hexNonce> <hexCiphertext> <password>"
