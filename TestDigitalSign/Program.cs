using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.IO;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto.Generators;
using static iTextSharp.text.pdf.security.CertificateInfo;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1;
using System.Collections;
using Org.BouncyCastle.Utilities;
using iTextSharp.text.pdf;

namespace TestDigitalSign
{
    class Program
    {
        static void Main(string[] args)
        {
            string subjectName = "testsubject";

            var randomGenerator = new CryptoApiRandomGenerator();

            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();

            var serialNumber =
    BigIntegers.CreateRandomInRange(
        BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            const string signatureAlgorithm = "SHA256WithRSA";
            certificateGenerator.SetSignatureAlgorithm(signatureAlgorithm);

            var subjectDN = new Org.BouncyCastle.Asn1.X509.X509Name(subjectName);
            var issuerDN = subjectDN;
            certificateGenerator.SetIssuerDN(issuerDN);
            certificateGenerator.SetSubjectDN(subjectDN);

            var notBefore = DateTime.UtcNow.Date;
            var notAfter = notBefore.AddYears(2);

            certificateGenerator.SetNotBefore(notBefore);
            certificateGenerator.SetNotAfter(notAfter);

            const int strength = 2048;
            var keyGenerationParameters = new KeyGenerationParameters(random, strength);

            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(keyGenerationParameters);
            var subjectKeyPair = keyPairGenerator.GenerateKeyPair();

            certificateGenerator.SetPublicKey(subjectKeyPair.Public);

            var issuerKeyPair = subjectKeyPair;
            var certificate = certificateGenerator.Generate(issuerKeyPair.Private, random);


            PdfReader reader = new PdfReader(this.inputPDF);

            ////var kpgen = new RsaKeyPairGenerator();

            ////kpgen.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024));

            ////var kp = kpgen.GenerateKeyPair();

            ////var gen = new X509V3CertificateGenerator();

            ////var certName = new Org.BouncyCastle.Asn1.X509.X509Name("CN=" + subjectName);
            ////var serialNo = BigInteger.ProbablePrime(120, new Random());

            ////gen.SetSerialNumber(serialNo);
            ////gen.SetSubjectDN(certName);
            ////gen.SetIssuerDN(certName);
            ////gen.SetNotAfter(DateTime.Now.AddYears(100));
            ////gen.SetNotBefore(DateTime.Now.Subtract(new TimeSpan(7, 0, 0, 0)));
            ////gen.SetSignatureAlgorithm("MD5WithRSA");
            ////gen.SetPublicKey(kp.Public);

            ////gen.AddExtension(
            ////    X509Extensions.AuthorityKeyIdentifier.Id,
            ////    false,
            ////    new AuthorityKeyIdentifier(
            ////        SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(kp.Public),
            ////        new GeneralNames(new GeneralName(certName)),
            ////        serialNo));

            ////gen.AddExtension(
            ////    X509Extensions.ExtendedKeyUsage.Id,
            ////    false,
            ////    new ExtendedKeyUsage(new ArrayList() { new DerObjectIdentifier("1.3.6.1.5.5.7.3.1") }));

            ////var newCert = gen.Generate(kp.Private);

            ////DotNetUtilities.ToX509Certificate(newCert).Export(System.Security.Cryptography.X509Certificates.X509ContentType.Pkcs12, "password");
        }
    }
}
