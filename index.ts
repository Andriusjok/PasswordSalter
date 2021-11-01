import { promisify } from "util";
import path from "path";
import fs, { createReadStream } from "fs";
import { createInterface } from "readline";
import Crypto from "crypto";

const fsReaddir = promisify(fs.readdir);
const fsLstat = promisify(fs.lstat);

const CONFIG = {
  saltLength: 5,
  pepper: "t68uK",
};

type PasswordAndSalt = {
  password: string;
  passwordHash: string;
  salt: string;
  saltedAndPepperedPassword: string;
  saltedAndPepperedPasswordHash: string;
};

var matchingPasswords: PasswordAndSalt[] = [];

async function searchFilesInDirectoryAsync(dir: string, ext: string) {
  const files = await fsReaddir(dir).catch((err) => {
    throw new Error(err.message);
  });
  const found = await getFilesInDirectoryAsync(dir, ext);

  searchForPasswords(found);
}

async function getFilesInDirectoryAsync(
  dir: string,
  ext: string
): Promise<string[]> {
  let files: string[] = [];
  const filesFromDirectory = await fsReaddir(dir).catch((err) => {
    throw new Error(err.message);
  });

  for (let file of filesFromDirectory) {
    const filePath = path.join(dir, file);
    const stat = await fsLstat(filePath);

    if (path.extname(file) === ext) {
      files.push(filePath);
    }
  }

  return files;
}

async function searchForPasswords(fileList: string[]): Promise<void> {
  for (let file of fileList) {
    readStream(file);
  }
}

const readStream = async (filePath: string) => {
  const readLine = createInterface({
    input: createReadStream(filePath),
    output: process.stdout,
    terminal: false,
  });

  readLine.on("line", (line) => {
    var randomSalt = Crypto.randomBytes(CONFIG.saltLength)
      .toString("base64")
      .slice(0, CONFIG.saltLength);
    var passwordAndSalt: PasswordAndSalt = {
      password: line,
      passwordHash: Crypto.createHash("sha256").update(line).digest("hex"),
      salt: randomSalt,
      saltedAndPepperedPassword: line + randomSalt + CONFIG.pepper,
      saltedAndPepperedPasswordHash: Crypto.createHash("sha256")
        .update(line + randomSalt + CONFIG.pepper)
        .digest("hex"),
    };
    matchingPasswords.push(passwordAndSalt);

    if (matchingPasswords.length == 100) {
      outputSaltCsv();
    }
  });
};

function outputSaltCsv() {
  for (let i = 0; i < matchingPasswords.length; i++) {
    console.log(
      `${matchingPasswords[i].password}, ${matchingPasswords[i].passwordHash}, ${matchingPasswords[i].salt}, ${CONFIG.pepper}, ${matchingPasswords[i].saltedAndPepperedPassword}, ${matchingPasswords[i].saltedAndPepperedPasswordHash}\n`
    );
  }
}

async function main() {
  await searchFilesInDirectoryAsync("./", ".txt");
}

if (require.main === module) {
  main();
}
