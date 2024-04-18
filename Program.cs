using System.Security.Cryptography.X509Certificates;
using System.IO.Packaging;
using CommandLine;

public class Options
{
  [Option('k', "package", Required = true, HelpText = "The package to sign")]
  public string? Package { get; set; }

  [Option('c', "certificate", Required = true, HelpText = "The certificate to use for signing")]
  public string? Certificate { get; set; }
}

public static class HCK
{
  public static void Sign(string package, X509Certificate2 certificate)
  {
    // Open the package to sign it
    Package packageToSign = Package.Open(package);

    // Specify that the digital signature should exist 
    // embedded in the signature part
    PackageDigitalSignatureManager signatureManager = new PackageDigitalSignatureManager(packageToSign);

    signatureManager.CertificateOption = CertificateEmbeddingOption.InCertificatePart;

    // We want to sign every part in the package
    List<Uri> partsToSign = new List<Uri>();
    foreach (PackagePart part in packageToSign.GetParts())
    {
      partsToSign.Add(part.Uri);
    }

    // We will sign every relationship by type
    // This will mean the signature is invalidated if *anything* is modified in                           //the package post-signing
    List<PackageRelationshipSelector> relationshipSelectors = new List<PackageRelationshipSelector>();

    foreach (PackageRelationship relationship in packageToSign.GetRelationships())
    {
      relationshipSelectors.Add(new PackageRelationshipSelector(relationship.SourceUri, PackageRelationshipSelectorType.Type, relationship.RelationshipType));
    }

    try
    {
      signatureManager.Sign(partsToSign, certificate, relationshipSelectors);
    }
    finally
    {
      packageToSign.Close();
    }
  }

  static void Main(string[] args)
  {
    Parser.Default.ParseArguments<Options>(args).WithParsed<Options>(o =>
    {
      if (o.Certificate != null && o.Package != null)
      {
        // Create a certificate
        X509Certificate2 certificate = new(o.Certificate);
        // Sign the package
        Sign(o.Package, certificate);
      }
    });
  }
}

