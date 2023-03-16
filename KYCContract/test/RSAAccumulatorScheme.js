// We import Chai to use its asserting functions here.
const { expect } = require("chai");
const { ethers } = require("hardhat");
let obj = require("../src/js/testAddress.js");
const { BigNumber } = require("../src/js/bignumber.js");

let testAddr = obj.array;

const lengthChoose = 12;

describe("KYC contract", function () {
  console.log(testAddr[0]);
});

/********************************************************    Accumulator      **************************************************************************************/
/*
 https://alinush.github.io/2020/11/24/RSA-accumulators.html
 p,q->prime
 N=pq
 fn=(p-1)(q-1)
 ****************** why fn is private？ ******************
 see:  https://crypto.stackexchange.com/questions/5791/why-is-it-important-that-phin-is-kept-a-secret-in-rsa
 *********************************************************
 */
//param 1: N -> public
//         fn-> private

class ModNumber {
  constructor(p, q) {
    this.N = p.times(q);
    this.p = p;
    this.q = q;
    this.fn = (q.minus(1)).times(p.minus(1));
  }
}


const modNum = new ModNumber(BigNumber(12026655772210679470465581609002525329245773732132014742758935511187863487919026457076252932048619706498126046597130520643092209728783224795661331197604583), BigNumber(8002511426596424351829267099531651390448054153452321185350746845306277585856673898048740413439442356860630765545600353049345324913056448174487017235828857));
console.log("RSA1024 = " + BigNumber(135066410865995223349603216278805969938881475605667027524485143851526510604859533833940287150571909441798207282164471551373680419703964191743046496589274256239341020864383202110372958725762358509643110564073501508187510676594629205563685529475213500852879416377328533906109750544334999811150056977236890927563))
const N = modNum.N;
const p = BigNumber(modNum.p);
const q = BigNumber(modNum.q);
const fn = modNum.fn;
console.log("modNum = " + N + " p = " + p
  + "q = " + q + " p-1 = " + (p.minus(1))
  + " q-1 = " + (q.minus(1)) + " fn = " + fn)


function powInMod(a, y, z) {
  let x = BigNumber(1);
  while (y.comparedTo(0) == 1) {
    if (y.mod(2).toNumber() === 1) {
      x = (x.times(a)).mod(z);
      y = y.minus(1);
    }
    y = y.div(2);
    a = a.times(a).mod(z);
  }
  return x;
}


class RSAaccumulator {

  static addItemToAccumulator(accumulator, value) {
    return powInMod(accumulator, value, N);
  }

  static deleteItemFromAccumulator(accumulator, value, inclusionProofOfValue) {
    if (RSAaccumulator.checkInclusionProof(accumulator, inclusionProofOfValue) == false) {
      console.log(value.toNumber() + "is not a member of accumulator !")
      return accumulator
    }
    //inverse Of value mod fn
    let inverseOfvalue = modInverse(value, modNum.fn)
    let newAccumulator = powInMod(accumulator, inverseOfvalue, N)
    console.log("delete successed !")
    return newAccumulator
  }

  //get membership witness
  //The following article uses a tree-like recursive method to calculate the membership proof, reducing many repeated calculations
  //Blind, Auditable Membership Proofs, by Sander, Tomas and Ta-Shma, Amnon and Yung, Moti, in Financial Cryptography, 2001 
  static getProof(setValues, value, generator) {
    let proofvalue = generator;
    for (let i = 0; i < setValues.length; i++) {
      if (!setValues[i].eq(value)) {
        proofvalue = powInMod(proofvalue, setValues[i], N);
      }
    }
    //console.log("proofvalue = " + proofvalue + " value = " + value)
    return new RSAaccumulatorProof(value, proofvalue);
  }


  //check membership witness
  static checkInclusionProof(accumulator, proof) {
    //console.log("proofvalue = " + proof.proof + " value = " + proof.value)
    return accumulator.eq(powInMod(proof.proof, proof.value, N))
  }


  /*
  another way to get proof  
  ****** It won't work if the element is too big*******
  h = g^v, z = h^x, B = hash(h+z)
  b = h^(floor(x/B)), r = x mod B
  check: b^B * h^r = h^(B*floor(x/B) + (x modB)) = h^x = z
  */
  static getProof2(setValues, value, generator) {
    let h = BigNumber(generator).pow(value)
    let x = BigNumber(1)
    let z = BigNumber(1)
    //console.log("****** h = "+ h + "z = " + z)
    for (let i = 0; i < setValues.length; i++) {
      if (!setValues[i].eq(value)) {
        x = x.times(setValues[i])
      }
    }//z=h^x mod N
    z = powInMod(h, x, N)
    let m = BigNumber(h).plus(z)
    let B = BigNumber(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(m.toString()))).mod(123456789)
    const m1 = x.mod(B)
    const m2 = x.minus(m1)
    const fl = BigNumber(m2.div(B))
    let b = BigNumber(h).pow(fl)
    let r = x.mod(B)
    //console.log("h = " + h + " x = "+ x + " z = "+ z + " B = "+ B + " fl = "+ fl + " b = "+ b + " r = "+ r)
    return new RSAaccumulatorProof2(value, b, z, r)
  }

  //check: b^B * h^r = h^(B*floor(x/B) + (x modB)) = h^x = z
  static checkInclusionProof2(generator, value, proof2) {
    let p2 = proof2
    let h = BigNumber(generator).pow(value)
    let m = BigNumber(h).plus(p2.z)
    let B = BigNumber(ethers.utils.keccak256(ethers.utils.toUtf8Bytes(m.toString()))).mod(123456789)
    let x1 = BigNumber(p2.b).pow(B)
    let x2 = BigNumber(h).pow(p2.r)
    let result = (BigNumber(x1).times(x2)).mod(N)
    return result.eq(p2.z)
  }
}

class RSAaccumulatorProof {
  constructor(value, proofvalue) {
    this.value = value;
    this.proof = proofvalue;
  }
}
class RSAaccumulatorProof2 {
  constructor(value, b, z, r) {
    this.value = value;
    this.b = b;
    this.z = z;
    this.r = r;
  }
}

/*
find y^-1 mod (fn), fn =(p-1)(q-1)
a*fn + by = 1   ----->    a*fn + by mod(fn) = by mod(fn) = 1 mod(fn)
*/
function modInverse(y, fn) {
  const [a, b, g] = extendedGcd(fn, y);
  let result = b.mod(fn)
  while (result.lt(0)) {
    result = result.plus(fn)
  }
  return result;
}


/*
 
Shamir's trick:
The trick is to compute integers 𝑎,𝑏  s.t. 𝑎.x + 𝑏.y = 1.
@return returnValue^(xy) = p1^x = p2^y = c modn
Detail:
returnValue = w1*w2 = p1^b * p2^a modn
returnValue^(xy) modn= p1^bxy * p2^axy modn= (p1^x)^by * (p2^y)^ax modn = c^(ax + by)modn = c modn
*/

function shamirTrick(p1, p2, x, y, n) {
  const [a, b, g] = extendedGcd(x, y);
  let w1 = p1.pow(BigNumber(b).toNumber()).mod(n.toNumber())
  let w2 = p2.pow(BigNumber(a).toNumber()).mod(n.toNumber())
  let result = (w1.times(w2.toNumber())).mod(n.toNumber())
  //console.log("w1 = " + w1.toNumber() + " w2 = "+ w2.toNumber() + "w1.times(w2).mod(n) = " + result)
  return result
}

/*
  Extended GCD algorithm.
  @return a,b,gcd(x,y)
 */
function extendedGcd(x, y) {
  //console.log("1 x = " + x + " y = " + y)
  if (x.isZero()) {
    const a = BigNumber(0)
    const b = BigNumber(1)
    const gcd = y
    //console.log("x = " + x + " a = " + a.toNumber() + " b = " + b.toNumber()  + " gcd = " + gcd.toNumber())
    //console.log("x = " + x + " ax + by = " + (a.times(x).plus(b.times(y))).toNumber())
    return [BigNumber(a), BigNumber(b), BigNumber(gcd)]
  }
  const [a1, b1, g1] = extendedGcd(y.mod(x), x)
  //Math.floor will lose precision, so it should be as follows
  const m1 = y.mod(x)
  const m2 = y.minus(m1)
  const ydx = BigNumber(m2.div(x))
  //const ydx = Math.floor(BigNumber(y.div(x)))
  //console.log("y.div(x) = " + y.div(x) + " ydx = " + ydx)
  const a = b1.minus(BigNumber(ydx).times(a1))
  const b = a1
  const gcd = g1
  //console.log("a = " + a.toNumber() + " b = " + b.toNumber()  + " gcd = " + gcd.toNumber())
  //console.log("2 x = " + x + " y = " + y)
  //console.log("ax + by = " + (a.times(x).plus(b.times(y))).toNumber())
  return [BigNumber(a), BigNumber(b), BigNumber(gcd)]
}
/******************************* test time  **********************************************/
/*
The computer configuration used for this experiment is :
[mac OS , 8-core Intel Core i9 2.3 GHz]

According to the test, about 5700 Keccak operations with an input size of 32 Byte can be performed per second.
The time spent on each operation is about 6 times longer than the time spent on Keccak.

The result of 100000 operations:
SHA3 time = 17463 ms
probablyPrime time = 101254 ms

If the parameter l is selected as 15, the number of calculations needed is 16^13 = 4.5*10^15, and the total time needed is about seconds about 158548 years. 
If l=17, the number of calculations required is 16^15=1.15*10^18.

From this point of view, the choice of parameter l = 17 is sufficient to ensure security.

*/


function timeTest(times){
  // SHA3 time
  let t1 = times;
  let t2 = times;
  let start1 = getTime()
  while(t1>0){
    t1--;
    ethers.utils.keccak256(ethers.utils.toUtf8Bytes(testAddr[t1%80]));
  }
  let end1 = getTime()
 

   // probablyPrime time
  let start2 = getTime()
  while(t2>0){
    t2--;
    let addrToHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(testAddr[t2%80]));
    let addrBN = BigNumber(addrToHash.substring(0, lengthChoose))
    let isprime = probablyPrime(addrBN, 7)
  }
  let end2 = getTime()
  let time1 = end1-start1
  let time2 = end2-start2-time1
  console.log("SHA3 time = " + time1 + " ms")
  console.log("probablyPrime time = " + time2 + " ms")

}


timeTest(100000);


/******************************* hashToPrime  **********************************************/
// hashToPrime
//test input wallet addresses data : src/js/testAddress.js
//test result:hashToPrimeTestResult.txt, TestData(l=*).log
function hashToPrime(address) {
  //lengthChoose is the param 'l' in the article
  //lengthChoose = 17 (including 0x)
 
  let addrToHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(address));
  //console.log("1st : " + addrToHash)
  let addrBN = BigNumber(addrToHash.substring(0, lengthChoose))
  let probablyPrimeTimes = 0
  let start = getTime()
  while (1) {
    probablyPrimeTimes++;
    let isprime = probablyPrime(addrBN, 7)
    if (isprime == true) {
      console.log("addrToHash is : " + addrToHash)
      let end = getTime()
      console.log("probablyPrime times = " + probablyPrimeTimes)
      console.log("time used : " + (end - start) + " ms ")
      console.log("!!! find prime = " + addrBN.toNumber() + " for " + address)
      totalFindTime += end - start

      totalLoopTimes += probablyPrimeTimes //totalLoopTimes counts the number of ProbablyPrime prime tests
      loggestFindTime = (end - start) > loggestFindTime ? (end - start) : loggestFindTime
      shortestFindTime = (end - start) < shortestFindTime ? (end - start) : shortestFindTime

      break;
    } else {
      let addrToHash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes(addrToHash))
      addrBN = BigNumber(addrToHash.substring(0, lengthChoose))
    }
  }
  return addrBN;
}

/*
Deterministic variant of Miller-Rabin test 
n -> the number to be tested (BigNumber) 
k -> the number of test cycles
*/
function probablyPrime(n, k) {

  if (n.toNumber() === 2 || n.toNumber() === 3)
    return true;
  if (n.mod(2).toNumber() === 0 || n.toNumber() < 2)
    return false;

  //Write (n - 1) as 2^s * d
  //k = s, q = d
  let s = 0, d = BigNumber(n.toNumber() - 1);
  while ((d.mod(2)).toNumber() === 0) {
    d = d.div(2);
    ++s;
  }

  /*
  The best known SPRP bases sets
  https://zh.wikipedia.org/wiki/%E7%B1%B3%E5%8B%92-%E6%8B%89%E5%AE%BE%E6%A3%80%E9%AA%8C#cite_note-1
  https://miller-rabin.appspot.com/
  20-04-2011	at least 2^64	[2, 3, 5, 7, 11, 13, 17]
  */
  let asss = [2, 3, 5, 7, 11, 13, 17]
  let j = 0
  WitnessLoop: do {

    //a : A base between 2 and n - 2
    //let nx = n.toNumber() - 3
    //let nxx = 2 + Math.floor(Math.random() * nx)
    // let a = BigNumber(nxx)//
    let a = BigNumber(asss[k - 1])

    let x = powInMod(a, d, n)
    // console.log("a = " + a.toNumber() + " x = " + x.toNumber())
    //1， if a^q mod n =1, then "not sure"
    if (x.toNumber() === 1)
      //console.log("pass con 1")
      continue;//pass
    //2， for(j=0 to k-1) do
    //       if a^(2^j * q) mod n =1, then "not sure"
    
    for (j = 0; j < s; j++) {
      let t = Math.pow(2, j) * d
      let r = powInMod(a, BigNumber(t), n)
      if (r.toNumber() === (n.toNumber() - 1))
        //console.log("pass con 2")
        continue WitnessLoop;//pass
    }
    if (j == s)
      return false//2 not satisfied
  } while (--k);

  return true;
}

function getTime() {
  let now = Date.now();
  return now
}

/******************************* Test Accumulator  **********************************************/
let totalLoopTimes = 0
let totalFindTime = 0
let loggestFindTime = 0
let shortestFindTime = 99999999999999

const NumberOfElements = 10 //Addresses of testAddr, max=80

let littleCoins = [
  BigNumber(2),
  BigNumber(3),
  BigNumber(5),
  BigNumber(7),
  BigNumber(11),
  BigNumber(13),
]

let coins = new Array();
for (let i = 0; i < NumberOfElements; i++) {
  let addrToPrime = hashToPrime(testAddr[i])
  coins[i] = addrToPrime
}

console.log("*****  averageFindTime = " + totalFindTime / NumberOfElements + " ms")
console.log("*****  averageLoopTimes = " + totalLoopTimes / NumberOfElements)
console.log("*****  loggestFindTime = " + loggestFindTime + " ms")
console.log("*****  shortestFindTime = " + shortestFindTime + " ms")

let coinswithout2 = new Array();
for (let i = 0; i < NumberOfElements; i++) {
  if (i != 2) {
    let addrToPrime = hashToPrime(testAddr[i])
    coins[i] = addrToPrime
  }
}


//accumulator test
let addrNotIn = hashToPrime("0x668Ce7e737eAb599697Cfb634509A7E0e6052b39@ETH")

const generator = BigNumber(65537);
let accumulator = generator;
console.log("accumulator before" + accumulator)
for (i = 0; i < coins.length; i++) {//add Item To Accumulator
  accumulator = RSAaccumulator.addItemToAccumulator(accumulator, coins[i]);
  console.log("accumulator add after" + coins[i].toNumber() + " is " + accumulator.toFixed())
}


describe("Check Test", function () {

  describe("HashToPrime test", function () {

    it("Should find the same prime each time", async function () {
      let addrToPrime1 = hashToPrime(testAddr[0])
      let addrToPrime2 = hashToPrime(testAddr[0])
      expect(addrToPrime1 == addrToPrime2);
    });

  });

  describe("Accumulator test", function () {

    it("Coins[lastObject] should be in the accumulator", async function () {
      const proof1 = RSAaccumulator.getProof(
        coins,
        coins[coins.length - 1],
        generator
      )
      console.log("proof1.value = " + proof1.value.toFixed() + "  proof1.proof = " + proof1.proof.toFixed())
      expect(RSAaccumulator.checkInclusionProof(accumulator, proof1) == true);
    });

    it("'addrNotIn' should be not in the accumulator", async function () {
      const proof2 = RSAaccumulator.getProof(
        coins,
        addrNotIn,
        generator
      )
      expect(RSAaccumulator.checkInclusionProof(accumulator, proof2) == false);
    });

    it("Test modInverse", async function () {
      let y = coins[2]
      console.log("Test modInverse: fn = " + modNum.fn + " y = " + y.toNumber())
      let inverseOfy = modInverse(y, modNum.fn)
      let vn = inverseOfy.times(y).mod(modNum.fn)
      console.log("Test modInverse: vn should be 1 ,vn = " + vn)
      expect(vn == 1);
    });

    it("Test delete Item", async function () {
      const proofInOfcoins2 = RSAaccumulator.getProof(
        coins,
        coins[2],
        generator
      )
      //coins[2] was in the accumulator
      let newAccmulatorRight = RSAaccumulator.deleteItemFromAccumulator(accumulator, coins[2], proofInOfcoins2)
      console.log("delete after = " + newAccmulatorRight)
      const proof11 = RSAaccumulator.getProof(
        coinswithout2,
        coins[2],
        generator
      )
      expect(RSAaccumulator.checkInclusionProof(newAccmulatorRight, proof11) == false);
    });

  });

});



