'use strict'

const crypto = require('crypto')
const fs = require('fs')
const log = require('./utils/log')

/* Arguments that can be passed are
 * --secret <secretKey>  | -s <secretKey>
 * --out <file-path> | -o <file-path>
 * --algo <algoName> |  -a <algoName>
 * --decrypt | -d 
 * --env <environment>
 * --folder <folder-where-encrypted-decrypted-files-live> currently in use only with --env. Do not suffix with /
 */

module.exports.decrypt = (options) => {
  try {
    const secret = options.secret || 'mySecret'
    const decryptionAlgo = options.decryptionAlgo || 'aes256'
    const ivLength = options.ivLength || 16
    const environment = options.environment;
    const folder = options.folder ? `${options.folder}/` : '';
    
    let outputFile = options.outputFile
    let inputFile = options.inputFile || '.env.enc'
    if(environment){
      outputFile = `${folder}.env.${environment}`
      inputFile = `${folder}.env.${environment}.enc`
    }

    if (!fs.existsSync(inputFile)) throw `${inputFile} does not exist.`
    if (!secret || typeof (secret) !== 'string') throw 'No SecretKey provided.'

    const fileBuffer = fs.readFileSync(inputFile)
    const iv = fileBuffer.slice(0, ivLength)
    const ciphertext = fileBuffer.slice(ivLength, fileBuffer.length)
    const key = crypto.createHash('sha256').update(String(secret)).digest()
    const decipher = crypto.createDecipheriv(decryptionAlgo, key, iv)
    let decrypted = decipher.update(ciphertext, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    
    if(outputFile){
      fs.writeFile(outputFile, decrypted, function(error) {
        if(error){
          return error;
        }
        return `The Environment file ${inputFile} has been decrypted to ${outputFile}`, 'info'
      });
    }
    else{
      return decrypted
    }
  } catch (e) {
    log(e, 'error')
  }
}

module.exports.encrypt = (options) => {
  try {
    const environment = options.environment;
    const secret = options.secret || 'mySecret'
    const encryptionAlgo = options.encryptionAlgo || 'aes256'
    const ivLength = options.ivLength || 16
    const folder = options.folder ? `${options.folder}/` : '';
    let inputFile = options.inputFile || '.env'
    let outputFilePath = options.outputFile || `${inputFile}.enc`

    if(environment){
      inputFile = `${folder}.env.${environment}`
      outputFilePath = `${folder}.env.${environment}.enc`
    }

    // presumably createCipheriv() should work for all the algo in ./openssl_list-cipher-algorithms.csv with the right key/iv length

    if (!fs.existsSync(inputFile)) throw `Error: ${inputFile} does not exist.`
    if (!secret || typeof (secret) !== 'string') throw 'No SecretKey provided.Use -s option to specify secret'

    const key = crypto.createHash('sha256').update(String(secret)).digest() // node v10.5.0+ should use crypto.scrypt(secret, salt, keylen[, options], callback)
    const iv = crypto.randomBytes(ivLength)
    const cipher = crypto.createCipheriv(encryptionAlgo, key, iv)
    const output = fs.createWriteStream(outputFilePath)
    output.write(iv)
    fs.createReadStream(inputFile).pipe(cipher).pipe(output)

    output.on('finish', () => {
      log(`The Environment file "${inputFile}" has been encrypted to "${outputFilePath}".`, 'info')
      log(`Make sure to delete "${inputFile}" for production use.`, 'warn')
    })
  } catch (e) {
    log(e, 'error')
  }
}
