## 🛡️ Uygulama Güvenliğine Yolculuk

Uygulama güvenliği, modern yazılım geliştirme süreçlerinin ayrılmaz bir parçasıdır. 

Günümüzün bağlantılı dünyasında, veri ihlalleri ve siber saldırılar hem finansal hem de itibari açıdan yıkıcı sonuçlar doğurabilir. Güvenli uygulamalar, kullanıcı güvenini sağlamanın ve yasal düzenlemelere (örneğin GDPR, HIPAA) uyum sağlamanın temelini oluşturur. Yazılım geliştiriciler, güvenlik gereksinimlerini tasarımın erken aşamalarına entegre ederek, "güvenliği tasarıma dahil etme" (security by design) yaklaşımını benimsemelidir. Bu yaklaşım, güvenlik açıklarının yaşam döngüsünün ilerleyen aşamalarında tespit edilmesinden kaynaklanan maliyetli yeniden çalışmaların önüne geçer ve daha sağlam bir güvenlik duruşu sağlar. 

---

## 🔰 Uygulama Güvenliği Temelleri

### Güvenli Tasarım Prensipleri

**En Az Ayrıcalık (Least Privilege):** Kullanıcıların ve süreçlerin, görevlerini yerine getirmek için yalnızca kesinlikle gerekli olan izinlere sahip olması prensibidir (POLP). Bu uygulama, bir güvenlik ihlali durumunda saldırganların erişebileceği sistemleri sınırlar. Rol Tabanlı Erişim Kontrolü (RBAC) bunun yaygın bir uygulamasıdır. POLP'nin sadece insan kullanıcılar için değil, API entegrasyonları ve otomatikleştirilmiş betikler gibi insan olmayan kimlikler için de geçerli olması, modern dağıtık sistemlerde saldırı yüzeyini daraltmanın kritik bir yoludur. POLP'nin kapsamının genişlemesi, mikroservis mimarileri ve otomasyonun yaygınlaşmasıyla doğrudan ilişkilidir. Her bir servisin veya otomasyon betiğinin yalnızca ihtiyaç duyduğu kaynaklara erişiminin olması, bir bileşenin ele geçirilmesi durumunda yatay hareket (lateral movement) riskini büyük ölçüde azaltır. Bu, güvenlik ihlallerinin etkisini minimize etme (containment) stratejisinin temelini oluşturur.   

**Görev Ayrılığı (Separation of Duties):** Anahtar sorumlulukların birden fazla kullanıcı veya sisteme dağıtılması, tek bir hata noktasını (single point of failure) önler. Bu, hiçbir tek kişinin hassas eylemler üzerinde kontrol sahibi olmamasını sağlar ve içeriden gelen tehditleri veya yanlış yapılandırmaları azaltır. Örneğin, geliştiricilerin kod yazma ve onaylama sorumluluğunu aynı anda taşımaması, akran kod incelemeleri ve otomatik güvenlik kontrolleri ile hesap verebilirliği sağlar.   

**Açık Tasarım (Open Design):** Güvenliğin iyi test edilmiş, şeffaf korumalara dayanması gerektiğini belirtir. Bir sistemin nasıl çalıştığını anlamakla saldırganların sistemi kıramaması gerekir. Geliştiriciler, zafiyet bırakmamak için genel olarak gözden geçirilmiş şifreleme standartları (AES, RSA) ve iyi belgelenmiş kimlik doğrulama mekanizmaları kullanmalıdır. Açık tasarım prensibi, "güvenlikte belirsizlik" (security by obscurity) kavramının tam tersidir. Bir sistemin iç işleyişi bilinse bile güvenli kalması gerektiği fikri, kriptografik sistemlerde özellikle önemlidir ve tescilli (proprietary) şifreleme yöntemlerinden kaçınılması gerektiğini vurgular. Bu yaklaşım, topluluk incelemesine ve akademik denetime izin vererek algoritmaların ve protokollerin zafiyetlerini daha hızlı ortaya çıkarır ve düzeltilmesini sağlar. Bu da yazılımın olgunluğunu ve dayanıklılığını artırır.   

**Derinlemesine Savunma (Defense in Depth):** Hiçbir tek güvenlik önleminin bir uygulamayı tamamen koruyamayacağı ilkesidir. Çoklu güvenlik kontrollerinin katmanlanması, saldırganların başarılı olmasını zorlaştırır. Güvenlik, Yazılım Geliştirme Yaşam Döngüsü'ne (SDLC) entegre edilmelidir (DevSecOps). Güvenlik duvarları, uç nokta koruması ve ağ segmentasyonu gibi katmanlar içerebilir. Derinlemesine savunma, bir güvenlik kontrolünün atlatılması durumunda diğer katmanların koruma sağlamaya devam etmesini garanti eder. Bu, özellikle karmaşık modern uygulamalar ve altyapılar için hayati öneme sahiptir, çünkü tek bir zayıf nokta tüm sistemi tehlikeye atabilir. Saldırganlar her zaman en zayıf halkayı arar; bu nedenle, her katmanda farklı türde kontrollerin olması (örneğin, ağ seviyesinde güvenlik duvarı, uygulama seviyesinde girdi doğrulama, veri seviyesinde şifreleme), bir saldırının ilerlemesini yavaşlatır veya tamamen durdurur. Bu durum, tespit ve yanıt için de daha fazla zaman tanır.   

**Güvenli Hata Durumu (Fail Securely):** Bir sistem hata ile karşılaştığında, hassas verileri açığa çıkarmak veya istenmeyen erişim sağlamak yerine güvenli bir duruma geçmelidir. Yanlış yapılandırılmış hata işleme, şiddetli zafiyetlere yol açabilir. Örnekler arasında oturum zaman aşımlarının uygulanması, beklenmedik girdilerin reddedilmesi ve dahili uygulama detaylarını ifşa eden hata mesajlarından kaçınılması yer alır.   

**Mekanizma Ekonomisi (Economy of Mechanism):** Aşırı karmaşık sistemler gereksiz riskler barındırır, denetlenmelerini ve bakımlarını zorlaştırır. Güvenlik kontrollerinin basitleştirilmesi, zafiyet ve yanlış yapılandırma olasılığını azaltır. Güvenli bir sistem, açık, özlü kod ve iyi belgelenmiş güvenlik önlemleri kullanmalıdır.

**Temel Güvenlik Kavramları: CIA Üçlüsü**

- **Gizlilik (Confidentiality):** Yetkisiz erişime karşı verinin korunması. Hassas verilerin sadece yetkili kişiler tarafından görülebilmesini sağlar.
- **Bütünlük (Integrity):** Verinin doğru ve tam olmasını, yetkisiz değişikliklere karşı korunmasını sağlar. Verinin oluşturulduğu andan itibaren bozulmamasını garanti eder.
- **Erişilebilirlik (Availability):** Yetkili kullanıcıların ihtiyaç duydukları zaman sistemlere ve verilere erişebilmelerini sağlar. Hizmet Reddi (DoS) saldırıları erişilebilirliği hedef alır.

---

## 🧭 Güvenlik Standartları ve Çerçeveleri

Güvenlik standartları ve çerçeveleri, organizasyonların güvenlik duruşlarını değerlendirmeleri ve iyileştirmeleri için yapılandırılmış bir yaklaşım sunar.

### 📌 OWASP Top 10

**OWASP (Open Worldwide Application Security Project)**, web uygulamaları için en kritik 10 güvenlik riskini listeleyen ve bu riskleri azaltmaya yönelik yönergeler sunan kar amacı gütmeyen bir kuruluştur. OWASP Top 10, geliştiricilerin güvenli kod yazmaları ve sağlam testler yapmaları için temel bir kaynaktır. Uygulamaların neredeyse yarısında OWASP Top 10'a giren bir güvenlik açığı bulunmuştur.   

OWASP Top 10'un web uygulamalarına odaklanmasına rağmen, benzer zafiyetlerin masaüstü uygulamalarında da kritik riskler oluşturması , güvenlik prensiplerinin platform bağımsız olduğunu ve temel zafiyet sınıflarının çoğu uygulama türü için geçerli olduğunu gösterir. Bu durum, bir yazılım mimarının güvenlik eğitimini sadece web'e değil, genel uygulama güvenliği prensiplerine yayması gerektiğini vurgular.   

![image](https://github.com/user-attachments/assets/3125bf95-f949-4382-83b1-4192a1d6225e)

### 🏛️ NIST Siber Güvenlik Çerçevesi (CSF)

NIST CSF, uygulamaları ve BT sistemlerini güvence altına almak için risk tabanlı bir yaklaşım sunar. Başlangıçta kritik altyapı için geliştirilmiş olsa da, kapsamlı bir siber güvenlik stratejisi arayan tüm kuruluşlar için bir standart haline gelmiştir. NIST CSF'nin "Risk Tabanlı Yaklaşım" vurgusu , güvenlik harcamalarının ve çabalarının en büyük etkiyi yaratacağı alanlara odaklanılması gerektiğini gösterir. Bu durum, her zafiyete eşit tepki vermek yerine, iş kritikliği ve saldırı olasılığına göre önceliklendirme yapmayı gerektirir. Bir yazılım mimarının sadece teknik zafiyetleri bilmekle kalmayıp, bu zafiyetlerin iş üzerindeki potansiyel etkisini (finansal kayıp, itibar kaybı, yasal yaptırımlar) de anlaması gerektiğini vurgular. Bu, teknik kararların iş hedefleriyle uyumlu olmasını sağlar ve güvenlik yatırımlarının haklı çıkarılmasına yardımcı olur. 

**Beş Temel Fonksiyon:**

- **Tanımla (Identify):** Kurumun sistemlerini, varlıklarını, verilerini ve yeteneklerini anlayarak siber güvenlik risklerini yönetmek için bir temel oluşturur. Bu, donanım ve yazılım envanterini çıkarmayı, riskleri belirlemeyi ve bir siber güvenlik politikası oluşturmayı içerir.
- **Koru (Protect):** Kritik hizmetlerin sunulmasını sağlamak için uygun güvenlik önlemlerini geliştirmek ve uygulamak. Bu, ağ erişimini izlemeyi, hassas dosyaları şifrelemeyi, verileri düzenli olarak yedeklemeyi, yazılımı güncel tutmayı ve çalışanlara güvenlik eğitimi vermeyi içerir.
- **Tespit Et (Detect):** Siber güvenlik olaylarının zamanında tespit edilmesini sağlamak için uygun faaliyetleri geliştirmek ve uygulamak. Bu, yetkisiz kullanıcıları veya anormal aktiviteleri gerçek zamanlı veya sonradan tespit etmek için mobil tehdit istihbaratı ve günlükleme/izleme araçları kullanmayı içerir.
- **Yanıt Ver (Respond):** Tespit edilen bir siber güvenlik olayına ilişkin faaliyetleri geliştirmek ve uygulamak. Bu, bir siber saldırı durumunda hasarı sınırlamak, müşterileri bilgilendirmek ve operasyonları sürdürmek için bir plana sahip olmayı içerir.
- **Kurtar (Recover):** Siber güvenlik olaylarının neden olduğu hizmet kesintilerini zamanında kurtarmak için uygun faaliyetleri geliştirmek ve uygulamak. Bu, saldırı sonrası neyin yanlış gittiğini belirlemeyi, etkilenen dosyaları kurtarmayı ve gelecekteki saldırıları önlemek için bir plan yapmayı ve paydaşlarla iletişim kurmayı içerir.   

----

## 🕳️ Güvenlik Açıkları ve Saldırı Yüzeyleri

Uygulamaların güvenlik açıklarını anlamak ve potansiyel saldırı yüzeylerini belirlemek, proaktif güvenlik stratejilerinin temelini oluşturur.

**Yaygın Güvenlik Açıkları**

**Enjeksiyonlar (Injections):** Güvenilmeyen verinin bir sorgu veya komutun parçası olarak yorumlayıcıya iletilmesiyle oluşur. Örnekler arasında SQL Injection (SQL sorgularına kötü niyetli kod enjekte etme), Cross-Site Scripting (XSS) (web sayfalarına kötü niyetli betik enjekte etme), LDAP, XML, OS komut enjeksiyonları bulunur. C#/.NET'te önlemek için parametreli sorgular (ADO.NET, Entity Framework), girdi doğrulama (input validation) ve çıktı kodlama (output encoding) kullanılmalıdır.   

**Bozuk Erişim Kontrolü (Broken Access Control):** Kullanıcıların yetkili olmadıkları kaynaklara veya işlevlere erişebilmesi. Zayıf erişim kontrolleri veya kimlik bilgisi yönetimi sorunları nedeniyle oluşur. C#/.NET'te önlemek için Rol Tabanlı Erişim Kontrolü (RBAC), politika tabanlı yetkilendirme, en az ayrıcalık prensibi ve sunucu tarafı yetkilendirme kontrolleri uygulanmalıdır.   

**Hassas Veri Maruziyeti (Sensitive Data Exposure):** Hassas bilgilerin (PII, finansal veriler, anahtarlar) kasıtsız olarak açığa çıkması. C#/.NET'te önlemek için veri şifreleme (transit ve at rest), güvenli anahtar yönetimi (Azure Key Vault, AWS KMS), loglarda hassas veri tutmaktan kaçınma ve bellek temizleme gibi yöntemler kullanılmalıdır.   

**Güvenlik Yanlış Yapılandırmaları (Security Misconfiguration):** Uygulama sunucuları, çerçeveler veya bulut altyapısındaki yanlış yapılandırmalar (geniş izinler, güvensiz varsayılanlar, açıklayıcı hata mesajları). Yanlış yapılandırma hatalarının 2021'de %10 arttığı ve kuruluşların %27'sinin ana sorun olarak bunu gösterdiği  gerçeği, yazılım mimarlarının ve DevOps ekiplerinin sadece kod güvenliğine değil, aynı zamanda altyapı ve uygulama yapılandırmalarına da odaklanması gerektiğini vurgular. Bu, DevSecOps'un "güvenliği sola kaydırma" prensibinin önemini artırır. Yanlış yapılandırmaların artışı, bulut benimsemesinin ve karmaşık dağıtılmış sistemlerin yaygınlaşmasının doğrudan bir sonucudur. Daha fazla yapılandırılabilir bileşen, daha fazla yanlış yapılandırma potansiyeli demektir. Bu durum, mimarların otomasyonu (Infrastructure as Code, Configuration as Code) ve sürekli denetimi (Configuration Management, Cloud Security Posture Management) güvenlik stratejilerine entegre etmelerini zorunlu kılar. C#/.NET'te önlemek için güvenli varsayılanlar, gereksiz servislerin kapatılması, sıkı izin yönetimi, detaylı hata mesajlarından kaçınma ve otomatik yapılandırma denetimi uygulanmalıdır.   

**Bilinen Zafiyetli Bileşenlerin Kullanımı (Vulnerable and Outdated Components):** Uygulamanın kullandığı üçüncü taraf kütüphanelerde veya işletim sistemi bileşenlerinde bilinen güvenlik açıklarının bulunması. C#/.NET'te önlemek için bağımlılık tarama araçları (SCA), düzenli güncellemeler, SBOM (Software Bill of Materials) kullanımı ve güvenilir paket kaynakları tercih edilmelidir.   

**Saldırı Yüzeyi Analizi**

Saldırı yüzeyi, bir saldırganın bir sisteme veya veriye yetkisiz erişim sağlamak için kullanabileceği tüm potansiyel giriş noktaları ve zayıf noktalarıdır. 

**Yaygın Saldırı Yüzeyleri:**

- Yanlış yapılandırılmış erişim kontrolleri (Misconfigured access controls)
- Yamalanmamış yazılım ve donanım (Unpatched software and hardware)
- Açık portlar ve servisler (Open ports and services)
- Zayıf ağ çevreleri (Weak network perimeters)
- Kimlik avı ve sosyal mühendislik (Phishing and social engineering)
- Güvenli olmayan API'ler (Insecure APIs)
- Güncel olmayan veya güvensiz şifreleme (Outdated or insecure encryption)
- Üçüncü taraf bağımlılıklar (Third-party dependencies)    

İnsan faktörünün toplam ihlallerin %74'ünde etkili olması , teknik güvenlik önlemlerinin yanı sıra sosyal mühendislik ve farkındalık eğitimlerinin de kritik bir saldırı yüzeyi azaltma stratejisi olduğunu gösterir. En sofistike teknik kontroller bile, insan hatası veya manipülasyonuyla aşılabilir. Saldırı yüzeyi analizi genellikle teknik zafiyetlere odaklanır. Ancak, güvenlik stratejisinin sadece yazılıma ve altyapıya değil, aynı zamanda kullanıcı eğitimine ve süreç güvenliğine de genişletilmesi gerektiğini gösteren bu durum, DevSecOps'taki "düzenli güvenlik eğitimi ve farkındalık" prensibiyle doğrudan bağlantılıdır.

---

## 🧑‍💻 Kimlik Doğrulama, Oturum ve Yetkilendirme

Bu üç kavram, bir uygulamanın güvenliğinin temel taşlarıdır ve kullanıcıların kim olduğunu, ne yapmalarına izin verildiğini ve bu izinlerin nasıl yönetildiğini belirler.

### 🔐 Kimlik Doğrulama (Authentication)

Bir kullanıcının veya sistemin iddia ettiği kişi veya varlık olduğunu doğrulama sürecidir.

**Kullanıcı Kaydı (RegisterModel.OnPostAsync):**

```csharp
public async Task<IActionResult> OnPostAsync(string returnUrl = null)
{
    returnUrl = returnUrl?? Url.Content("~/");
    if (ModelState.IsValid)
    {
        var user = new IdentityUser { UserName = Input.Email, Email = Input.Email };
        var result = await _userManager.CreateAsync(user, Input.Password);
        if (result.Succeeded)
        {
            _logger.LogInformation("User created a new account with password.");
            // E-posta onayı mantığı (GenerateEmailConfirmationTokenAsync, SendEmailAsync)
            if (_userManager.Options.SignIn.RequireConfirmedAccount)
            {
                return RedirectToPage("RegisterConfirmation", new { email = Input.Email });
            }
            else
            {
                await _signInManager.SignInAsync(user, isPersistent: false);
                return LocalRedirect(returnUrl);
            }
        }
        foreach (var error in result.Errors)
        {
            ModelState.AddModelError(string.Empty, error.Description);
        }
    }
    return Page();
}
```

**Kullanıcı Girişi (LoginModel.OnPostAsync):**

```csharp
public async Task<IActionResult> OnPostAsync(string returnUrl = null)
{
    returnUrl = returnUrl?? Url.Content("~/");
    if (ModelState.IsValid)
    {
        // Bu, hesap kilitleme için başarısız giriş denemelerini saymaz.
        // Parola hatalarının hesap kilitlemeyi tetiklemesini sağlamak için lockoutOnFailure: true olarak ayarlayın.
        var result = await _signInManager.PasswordSignInAsync(Input.Email,
                           Input.Password, Input.RememberMe, lockoutOnFailure: true); // lockoutOnFailure: true önemli!
        if (result.Succeeded)
        {
            _logger.LogInformation("User logged in.");
            return LocalRedirect(returnUrl);
        }
        if (result.RequiresTwoFactor) { /* 2FA sayfasına yönlendirme */ }
        if (result.IsLockedOut) { /* Kilitleme sayfasına yönlendirme */ }
        else { ModelState.AddModelError(string.Empty, "Invalid login attempt."); }
    }
    return Page();
}
```

**lockoutOnFailure:** true parametresinin PasswordSignInAsync metodunda kullanılması , brute-force saldırılarına karşı otomatik koruma sağlamanın kritik bir örneğidir. Bu, sadece doğru kimlik doğrulama değil, aynı zamanda kimlik doğrulama sürecinin kendisinin güvenliğini de sağlamak anlamına gelir. Parola denemeleriyle yapılan saldırılar (brute-force, dictionary attacks) çok yaygındır.    

**lockoutOnFailure:** true gibi mekanizmalar, bu tür saldırıları otomatik olarak yavaşlatarak veya engelleyerek uygulamanın savunmasını önemli ölçüde güçlendirir. Bu, sadece geliştiricinin güvenli kod yazması değil, aynı zamanda framework'ün sunduğu güvenlik özelliklerini doğru şekilde yapılandırması gerektiğini gösterir.

**Kullanıcı Çıkışı (LogoutModel.OnPost):**

```csharp
public async Task<IActionResult> OnPost(string returnUrl = null)
{
    await _signInManager.SignOutAsync();
    _logger.LogInformation("User logged out.");
    if (returnUrl!= null) { return LocalRedirect(returnUrl); }
    else { return RedirectToPage(); }
}
```

### 🪪 JWT (JSON Web Token) Tabanlı Kimlik Doğrulama

API'ler için yaygın olarak kullanılır. Kimlik sağlayıcı başarılı kimlik doğrulamasından sonra bir JWT veya token verir.   

**JWT Bearer Kimlik Doğrulaması Yapılandırması:**

```csharp
// NuGet paketlerini ekleyin:
// Microsoft.AspNetCore.Authentication.JwtBearer
// Microsoft.IdentityModel.Tokens
// System.IdentityModel.Tokens.Jwt

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
   .AddJwtBearer(jwtOptions =>
    {
        jwtOptions.Authority = builder.Configuration["Jwt:Authority"]; // Kimlik sağlayıcısı URL'si
        jwtOptions.Audience = builder.Configuration["Jwt:Audience"];   // Token'ın hedef kitlesi
        jwtOptions.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
        };
    });
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
//...
```

**Login Kontrolcüsünde Token Oluşturma Örneği:**

```csharp
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

//... (LoginController içinde)
[HttpPost("login")]
public IActionResult Login( LoginModel model)
{
    // Kullanıcı doğrulama mantığı (örneğin veritabanından)
    if (IsValidUser(model.Username, model.Password))
    {
        var claims = new
        {
            new Claim(JwtRegisteredClaimNames.Sub, model.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.Role, "Admin") // Örnek rol
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            claims: claims,
            expires: DateTime.Now.AddMinutes(30), // Token ömrü
            signingCredentials: creds
        );

        return Ok(new { Token = new JwtSecurityTokenHandler().WriteToken(token) });
    }
    return Unauthorized();
}
```

JWT kullanırken "ID token'ların API'lere gönderilmemesi" ve "Access token'ların UI uygulamalarında açılmaması" gerektiği uyarısı , token tabanlı kimlik doğrulamanın karmaşıklığını ve farklı token türlerinin farklı amaçlara hizmet ettiğini gösterir. Bu durum, geliştiricilerin sadece token kullanmakla kalmayıp, token akışlarını ve güvenlik modellerini derinlemesine anlamaları gerektiğini vurgular. ID token'lar kimlik doğrulama (kullanıcının kimliğini kanıtlama) içindir, Access token'lar ise yetkilendirme (kaynaklara erişim izni) içindir. Bu ayrım, güvenlik prensibi olan "least privilege" ile uyumludur. UI'da access token'ı açmak, hassas bilgileri istemci tarafında açığa çıkarabilir ve güvenlik riskleri yaratabilir. Bu nedenle, mimarın token türlerini ve kullanım senaryolarını net bir şekilde anlaması, doğru güvenlik mimarisi tasarlaması için elzemdir.

### 🔓 OAuth 2.0 ve OpenID Connect

**OAuth 2.0:** Yetkilendirme için kullanılır, kullanıcının kaynak sunuculara (API'ler) istemci uygulaması adına erişim izni vermesini sağlar.   

**OpenID Connect (OIDC):** OAuth 2.0 üzerine inşa edilmiş bir kimlik katmanıdır. Hem kimlik doğrulama hem de API erişimini tek bir protokolde birleştirir. Bir erişim token'ı ve kimliği doğrulanmış kullanıcı hakkında bilgi içeren bir ID token (JWT formatında) verir. 

appsettings.json'da yapılandırma:

```json
"OpenIDConnect": {
    "ClientId": "dotnet-client",
    "ClientSecret": "YOUR_CLIENT_SECRET",
    "Issuer": "http://login.example.com:8443/oauth/v2/oauth-anonymous",
    "Scope": "openid profile",
    "CallbackPath": "/callback",
    "PostLogoutRedirectUri": "http://www.example.com:5000",
    "TokenEndpoint": "http://login.example.com:8443/oauth/v2/oauth-token"
}
```

**Program.cs'de servis ekleme (örnekte AddOpenIdConnect kullanıldığı varsayılır):**

```csharp
//...
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
})
```

```csharp
.AddCookie()
.AddOpenIdConnect(options =>
{
builder.Configuration.GetSection("OpenIDConnect").Bind(options);
options.ResponseType = "code"; // Authorization Code Flow
// Diğer seçenekler (SaveTokens, GetClaimsFromUserInfoEndpoint vb.)
});
//...
```

OIDC'nin OAuth 2.0 üzerine bir kimlik katmanı eklemesi , modern kimlik ve erişim yönetimi çözümlerinin evrimini gösterir. OAuth 2.0 yetkilendirmeye odaklanırken, OIDC kimlik doğrulama eksikliğini gidererek daha bütünsel bir çözüm sunar. Bu durum, mimarların sadece "erişim" değil, aynı zamanda "kimlik" kavramını da güvenli bir şekilde yönetmeleri gerektiğini vurgular. OAuth 2.0, bir uygulamanın kullanıcının izniyle başka bir servise erişmesini sağlar, ancak kullanıcının kimliğini doğrulama işini kendi başına yapmaz. OIDC bu boşluğu doldurur. Bu, özellikle Tek Oturum Açma (Single Sign-On - SSO) ve birleşik kimlik (federated identity) senaryolarında önemlidir. Bir mimar, bu iki protokolün farkını ve birlikte nasıl çalıştığını net bir şekilde anlamalıdır.   

### 🧾 Oturum Yönetimi (Session Management)

Kullanıcı bir uygulamaya giriş yaptıktan sonra, uygulama ile kullanıcının etkileşimini sürdürme ve durumu koruma sürecidir.

**Güvenli Oturum Yönetimi Prensipleri:**

- Varsayılan SessionID'yi kullanmaktan kaçınılmalıdır.
- Varsayılan oturum çerez adı değiştirilmelidir (ASP.NET_SessionId gibi bilgileri açığa çıkarmamak için).
- Çıkış yaparken oturum çerezi geçersiz kılınmalı/silinmelidir.
- Yeni oturum çerezleri oluşturulmalıdır (giriş sonrası veya kritik eylemler sonrası).
- Oturum günlüklemesi yapılmalıdır (oluşturma, yok etme, anormallikler).
- Oturum token'larının benzersiz, rastgele ve tahmin edilemez olmasını sağlayın.
- Çerez bilgileri şifrelenmelidir.
- Hassas veriler oturum durumunda saklanmamalıdır.
- Kısa oturum zaman aşımları kullanılmalıdır.
- Oturum çerezlerinin HttpOnly ve Secure olarak işaretlendiğinden emin olunmalıdır.

```csharp
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDistributedMemoryCache(); // Oturum için bir IDistributedCache uygulaması gereklidir
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromSeconds(1200); // 20 dakika varsayılan, test için kısa tutulabilir
    options.Cookie.HttpOnly = true; // JavaScript erişimini engeller
    options.Cookie.IsEssential = true; // GDPR uyumluluğu için
    options.Cookie.Name = ".YourApp.Session"; // Varsayılan adı değiştirin
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Sadece HTTPS üzerinden gönder
});

var app = builder.Build();

//... diğer middleware'ler
app.UseRouting();
app.UseAuthentication(); // UseSession'dan önce olmalı
app.UseAuthorization();  // UseSession'dan önce olmalı
app.UseSession(); // UseRouting ve MapRazorPages/MapDefaultControllerRoute arasında olmalı
//...

// Oturum değerlerini ayarlama ve alma (örnek bir PageModel içinde)
public class IndexModel : PageModel
{
    public const string SessionKeyName = "_Name";
    public const string SessionKeyAge = "_Age";

    public void OnGet()
    {
        if (string.IsNullOrEmpty(HttpContext.Session.GetString(SessionKeyName)))
        {
            HttpContext.Session.SetString(SessionKeyName, "John Doe");
            HttpContext.Session.SetInt32(SessionKeyAge, 42);
        }
        var name = HttpContext.Session.GetString(SessionKeyName);
        var age = HttpContext.Session.GetInt32(SessionKeyAge)?.ToString();
        //...
    }
}

// Kompleks tipleri serileştirme/deserileştirme için extension metotları
public static class SessionExtensions
{
    public static void Set<T>(this ISession session, string key, T value)
    {
        session.SetString(key, JsonSerializer.Serialize(value));
    }

    public static T? Get<T>(this ISession session, string key)
    {
        var value = session.GetString(key);
        return value == null? default : JsonSerializer.Deserialize<T>(value);
    }
}
```

ASP.NET Core'da cookieless session özelliğinin güvensiz olduğu ve oturum sabitleme (session fixation) saldırılarına yol açabileceği için kaldırılması , framework'lerin güvenlik açıklarını kapatma ve geliştiricileri daha güvenli pratiklere yönlendirme rolünü gösterir. Bu durum, mimarların framework güncellemelerini takip etmelerinin ve eski, güvensiz özelliklerden kaçınmalarının önemini vurgular. Cookieless session'lar, oturum kimliğini URL'de veya gizli form alanlarında taşıyarak kolayca ele geçirilebilir ve yeniden kullanılabilir hale getirir. Bu, oturum sabitleme saldırılarına zemin hazırlar. Microsoft'un bu özelliği kaldırması, güvenlik topluluğunun en iyi uygulamalarını framework düzeyinde benimsemesinin bir sonucudur. Bu durum, geliştiricilerin framework'ün güvenlik kararlarını anlamaları ve bunlara uymaları gerektiğini gösterir.

### 🛂 Yetkilendirme (Authorization)

Bir kullanıcının veya sistemin belirli bir kaynağa erişme veya belirli bir eylemi gerçekleştirme iznine sahip olup olmadığını belirleme sürecidir.

**Rol Tabanlı Erişim Kontrolü (RBAC):** Kimlik oluşturulduğunda bir veya daha fazla role ait olabilir (örneğin, Yönetici, Kullanıcı). Bu rollerin oluşturulması ve yönetimi, yetkilendirme sürecinin arka plan deposuna bağlıdır.   

**Deklaratif Rol Kontrolleri:**

```csharp
// Sadece "Administrator" rolündeki kullanıcılara erişim izni verir

public class AdministrationController : Controller
{
    public IActionResult Index() => Content("Administrator Page");
}

// "HRManager" veya "Finance" rolündeki kullanıcılara erişim izni verir (OR logic)

public class SalaryController : Controller
{
    public IActionResult Payslip() => Content("Payslip for HR/Finance");
}

// Hem "PowerUser" hem de "ControlPanelUser" rolündeki kullanıcılara erişim izni verir (AND logic)


public class ControlPanelController : Controller
{
    public IActionResult Index() => Content("PowerUser AND ControlPanelUser Page");
}

// Kontrolcü seviyesinde yetkilendirme, aksiyon seviyesinde daha da kısıtlama

public class ControlAllPanelController : Controller
{
    public IActionResult SetTime() => Content("Set Time (Admin or PowerUser)");

    // Sadece Administrator
    public IActionResult ShutDown() => Content("Shutdown (Admin only)");
}

// Anonim erişime izin verme
[Authorize] // Kontrolcü seviyesinde yetkilendirme gerektirir
public class PublicController : Controller
{
    public IActionResult AuthorizedAction() => Content("Authorized content");

    [AllowAnonymous] // Bu aksiyon anonim erişime açık
    public IActionResult PublicAction() => Content("Public content");
}
```

**Politika Tabanlı Rol Kontrolleri:**

**Program.cs içinde politika tanımlama:**

```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("RequireAdministratorRole",
         policy => policy.RequireRole("Administrator"));

    options.AddPolicy("ElevatedRights", policy =>
          policy.RequireRole("Administrator", "PowerUser", "BackupAdministrator"));
});
//...
app.UseAuthentication();
app.UseAuthorization();
```

**Kontrolcü veya aksiyonda politika kullanma:**

```csharp
public IActionResult AdminDashboard()
{
    return View();
}
```

**En Az Ayrıcalık Prensibi (Principle of Least Privilege - POLP):** Kullanıcılara ve sistemlere görevlerini yerine getirmek için gereken minimum erişim düzeyini verme ilkesidir. RBAC'nin "en az ayrıcalık" prensibiyle birleşimi, yetkilendirme modelini sadece basitleştirmekle kalmaz, aynı zamanda güvenlik duruşunu önemli ölçüde güçlendirir. Kullanıcıların sadece ihtiyaç duydukları ayrıcalıklara sahip olması, bir hesabın ele geçirilmesi durumunda potansiyel hasarı sınırlar. RBAC, izinleri yönetmek için ölçeklenebilir bir yol sunar. Ancak RBAC'nin etkinliği, rollerin doğru tanımlanmasına ve bu rollere en az ayrıcalık prensibinin uygulanmasına bağlıdır. Eğer bir role gereğinden fazla izin verilirse, o rolü üstlenen herhangi bir kullanıcı potansiyel bir güvenlik riski haline gelir. Bu durum, mimarın rol tanımlarını dikkatlice yapması ve sürekli denetlemesi gerektiğini gösterir.   

---

## 🔒 Şifreleme, Hashleme ve PKI

Veri gizliliğini, bütünlüğünü ve kimlik doğrulamasını sağlamak için kriptografik yöntemler kritik öneme sahiptir.

**Şifreleme (Encryption)**

Veriyi yetkisiz kişilerin okuyamayacağı bir formata dönüştürme işlemidir.

**Simetrik Şifreleme (AES):** Aynı anahtarın hem şifreleme hem de şifre çözme için kullanıldığı hızlı bir yöntemdir. Veri depolama için idealdir.

```csharp
using System.Security.Cryptography;
using System.Text;
using System.IO;

public class AesEncryptor
{
    private const int KeySize = 256; // AES-256
    private const int BlockSize = 128; // 16 bytes IV

    public static EncryptionResult Encrypt(string plainText)
    {
        using (var aes = Aes.Create())
        {
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.GenerateKey(); // Her işlem için yeni anahtar
            aes.GenerateIV();  // Her işlem için yeni IV

            byte encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var msEncrypt = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                using (var swEncrypt = new StreamWriter(csEncrypt))
                {
                    swEncrypt.Write(plainText);
                }
                encryptedData = msEncrypt.ToArray();
            }
            return EncryptionResult.CreateEncryptedData(encryptedData, aes.IV, Convert.ToBase64String(aes.Key));
        }
    }

    public static string Decrypt(EncryptionResult encryptionResult)
    {
        var key = Convert.FromBase64String(encryptionResult.Key);
        var (iv, encryptedData) = encryptionResult.GetIVAndEncryptedData();

        using (var aes = Aes.Create())
        {
            aes.KeySize = KeySize;
            aes.BlockSize = BlockSize;
            aes.Key = key;
            aes.IV = iv;

            using (var decryptor = aes.CreateDecryptor())
            using (var msDecrypt = new MemoryStream(encryptedData))
            using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
            using (var srDecrypt = new StreamReader(csDecrypt))
            {
                try { return srDecrypt.ReadToEnd(); }
                catch (CryptographicException ex) { throw new CryptographicException("Decryption failed", ex); }
            }
        }
    }
}

public class EncryptionResult
{
    public string EncryptedData { get; set; } // IV prepended to encrypted data
    public string Key { get; set; }

    public static EncryptionResult CreateEncryptedData(byte data, byte iv, string key)
    {
        var combined = new byte[iv.Length + data.Length];
        Array.Copy(iv, 0, combined, 0, iv.Length);
        Array.Copy(data, 0, combined, iv.Length, data.Length);
        return new EncryptionResult { EncryptedData = Convert.ToBase64String(combined), Key = key };
    }

    public (byte iv, byte encryptedData) GetIVAndEncryptedData()
    {
        var combined = Convert.FromBase64String(EncryptedData);
        var iv = new byte; // AES block size is 16 bytes (128 bits)
        var encryptedData = new byte[combined.Length - 16];
        Array.Copy(combined, 0, iv, 0, 16);
        Array.Copy(combined, 16, encryptedData, 0, encryptedData.Length);
        return (iv, encryptedData);
    }
}
// Kullanım örneği:
// var apiKey = "your-sensitive-api-key";
// var encryptionResult = AesEncryptor.Encrypt(apiKey);
// // encryptedData'yı veritabanında, key'i Key Vault'ta saklayın
// var decryptedApiKey = AesEncryptor.Decrypt(encryptionResult);
```

AES şifrelemesinde her işlem için yeni bir anahtar ve IV (Initialization Vector) üretilmesi gerektiği , kriptografik güvenliğin sadece algoritma seçimiyle sınırlı olmadığını, aynı zamanda doğru kullanım pratikleriyle de ilgili olduğunu gösterir. Anahtar ve IV'nin tekrar kullanılması, şifrelemenin zayıflamasına yol açabilir. Ayrıca, anahtarın şifrelenmiş veriyle birlikte saklanmaması gerektiği vurgusu, anahtar yönetiminin kritikliğini ortaya koyar. Kriptografik algoritmalar matematiksel olarak sağlam olsa da, yanlış uygulanmaları onları işe yaramaz hale getirebilir. IV'nin amacı, aynı düz metnin farklı şifreli metinler üretmesini sağlamaktır (deterministik şifrelemeyi önlemek). Anahtarın veriyle aynı yerde saklanması, bir saldırganın her ikisine de erişmesi durumunda tüm şifrelemenin anlamsız hale gelmesine neden olur. Bu durum, mimarın sadece şifreleme algoritmalarını değil, aynı zamanda anahtar yönetimi ve kriptografik protokollerin doğru uygulamasını da anlaması gerektiğini gösterir. 

**Asimetrik Şifreleme (RSA):** 

Farklı anahtarların (bir genel, bir özel) şifreleme ve şifre çözme için kullanıldığı daha yavaş bir yöntemdir. SSL/TLS ve dijital imzalar için kullanılır.

```csharp
using System.Security.Cryptography;
using System.Text;

public class RsaEncryptor
{
    private RSACryptoServiceProvider rsa;

    public RsaEncryptor(int keySize = 2048) // Anahtar boyutu genellikle 2048 veya 4096 bit
    {
        rsa = new RSACryptoServiceProvider(keySize);
    }

    public string GetPublicKeyXml()
    {
        return rsa.ToXmlString(false); // Sadece genel anahtarı XML olarak dışa aktar
    }

    public string GetPrivateKeyXml()
    {
        return rsa.ToXmlString(true); // Hem genel hem de özel anahtarı XML olarak dışa aktar
    }

    public void LoadPrivateKey(string privateKeyXml)
    {
        rsa.FromXmlString(privateKeyXml);
    }

    public byte Encrypt(byte dataToEncrypt, string publicKeyXml, bool doOAEPPadding = true)
    {
        using (RSACryptoServiceProvider rsaPublic = new RSACryptoServiceProvider())
        {
            rsaPublic.FromXmlString(publicKeyXml); // Genel anahtarı içe aktar
            return rsaPublic.Encrypt(dataToEncrypt, doOAEPPadding);
        }
    }

    public byte Decrypt(byte dataToDecrypt, bool doOAEPPadding = true)
    {
        // Özel anahtarın mevcut olduğundan emin olun
        if (rsa.PublicOnly)
            throw new CryptographicException("Private key is not loaded for decryption.");

        return rsa.Decrypt(dataToDecrypt, doOAEPPadding);
    }
}
// Kullanım örneği:
// var rsaExample = new RsaEncryptor();
// string publicKey = rsaExample.GetPublicKeyXml();
// string privateKey = rsaExample.GetPrivateKeyXml(); // Özel anahtarı güvenli tutun!

// byte encryptedData = rsaExample.Encrypt(Encoding.UTF8.GetBytes("Sensitive Message"), publicKey);

// RsaEncryptor decryptor = new RsaEncryptor();
// decryptor.LoadPrivateKey(privateKey);
// byte decryptedData = decryptor.Decrypt(encryptedData);
// Console.WriteLine(Encoding.UTF8.GetString(decryptedData));
```

Asimetrik şifrelemenin daha yavaş olması , büyük veri setlerinin şifrelenmesinde pratik olmadığını gösterir. Bu nedenle, genellikle simetrik anahtarların güvenli bir şekilde değişimi için kullanılırken, asimetrik şifreleme daha küçük veri parçaları (örneğin, oturum anahtarları) veya dijital imzalar için tercih edilir. Bu durum, bir "hibrit şifreleme" yaklaşımına yol açar. Performans, şifreleme seçiminde önemli bir faktördür. RSA'nın matematiksel karmaşıklığı, onu AES gibi simetrik algoritmalara göre çok daha yavaş yapar. Bu nedenle, gerçek dünyada genellikle büyük veriler AES ile şifrelenir ve AES anahtarı RSA ile şifrelenerek güvenli bir şekilde aktarılır. Bu hibrit yaklaşım, hem performans hem de güvenlik avantajlarını birleştirir.   

**Hashleme (Hashing)**

Verinin sabit boyutlu, benzersiz bir özetine (hash) dönüştürülmesi işlemidir. Geri döndürülemezdir ve verinin bütünlüğünü doğrulamak için kullanılır.

**Parola Hashleme Algoritmaları**

MD5 veya SHA-256 gibi hızlı hash fonksiyonları parolalar için uygun değildir çünkü brute-force saldırılarına karşı savunmasızdırlar. Bunun yerine, kasıtlı olarak yavaş tasarlanmış, tuzlama (salting) ve iş faktörü (work factor/cost) gibi özelliklere sahip algoritmalar kullanılmalıdır.

- **BCrypt:** Otomatik olarak benzersiz bir tuz (salt) üretir ve gökkuşağı tabloları saldırılarını önler. Ayarlanabilir bir hesaplama maliyeti (work factor) ile brute-force saldırılarını zorlaştırır. 

- **Argon2:** Parola Hashleme Yarışması'nın (Password Hashing Competition) galibi olup, yan kanal (side-channel) ve GPU tabanlı saldırılara karşı mükemmel güvenlik sağlar. Argon2id, önerilen versiyondur. 

**Salt Kullanımı:** Her parolaya benzersiz, rastgele bir değer (salt) eklenerek hashlenir. Bu, aynı parolaların farklı hashler üretmesini sağlar ve gökkuşağı tabloları ile önceden hesaplanmış hash tablolarının kullanımını engeller.   

**BCrypt ile Parola Hashleme ve Doğrulama**

```csharp
// NuGet: Install-Package BCrypt.Net-Next
using BCrypt.Net;

public class PasswordHasher
{
    public static string HashPassword(string password)
    {
        // workFactor: 12 web uygulamaları için güçlü bir değerdir.
        // Daha yüksek değerler daha güvenlidir ancak daha yavaştır.
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
    }

    public static bool VerifyPassword(string enteredPassword, string storedHash)
    {
        return BCrypt.Net.BCrypt.Verify(enteredPassword, storedHash);
    }
}
// Kullanım örneği:
// string userPassword = "MySuperSecretPassword!";
// string hashedPassword = PasswordHasher.HashPassword(userPassword);
// // hashedPassword'ı veritabanında saklayın

// bool isValid = PasswordHasher.VerifyPassword(userPassword, hashedPassword);
// Console.WriteLine($"Password is valid: {isValid}");
```

**Argon2id ile Parola Hashleme ve Doğrulama**

```csharp
// NuGet: Install-Package Konscious.Security.Cryptography.Argon2
using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

public class Argon2idHasher
{
    private const int SaltSize = 16; // 128 bits
    private const int HashSize = 32; // 256 bits
    private const int DegreeOfParallelism = 8; // CPU çekirdeği sayısına göre ayarlanabilir
    private const int Iterations = 4; // Güvenlik ve performans dengesi
    private const int MemorySize = 1024 * 1024; // 1 GB (bellek maliyeti)

    public string HashPassword(string password)
    {
        byte salt = new byte;
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
        }

        byte hash = HashPasswordInternal(password, salt);

        var combinedBytes = new byte[salt.Length + hash.Length];
        Array.Copy(salt, 0, combinedBytes, 0, salt.Length);
        Array.Copy(hash, 0, combinedBytes, salt.Length, hash.Length);

        return Convert.ToBase64String(combinedBytes);
    }

    private byte HashPasswordInternal(string password, byte salt)
    {
        var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            DegreeOfParallelism = DegreeOfParallelism,
            Iterations = Iterations,
            MemorySize = MemorySize
        };
        return argon2.GetBytes(HashSize);
    }

    public bool VerifyPassword(string password, string hashedPassword)
    {
        byte combinedBytes = Convert.FromBase64String(hashedPassword);
        byte salt = new byte;
        byte hash = new byte;
        Array.Copy(combinedBytes, 0, salt, 0, SaltSize);
        Array.Copy(combinedBytes, SaltSize, hash, 0, HashSize);

        byte newHash = HashPasswordInternal(password, salt);

        // Sabit zamanlı karşılaştırma (timing attacks'ı önler)
        return CryptographicOperations.FixedTimeEquals(hash, newHash);
    }
}
// Kullanım örneği:
// var hasher = new Argon2idHasher();
// string userPassword = "MySecurePassword123!";
// string hashedPassword = hasher.HashPassword(userPassword);
// // hashedPassword'ı veritabanında saklayın

// bool isValid = hasher.VerifyPassword(userPassword, hashedPassword);
// Console.WriteLine($"Password is valid: {isValid}");
```

ASP.NET Core Identity'nin varsayılan olarak PBKDF2-HMAC-SHA256 kullanması ve bunun GPU tabanlı saldırılara karşı zayıf kabul edilmesi , framework'ün varsayılan güvenlik mekanizmalarının bile zamanla güncel tehditlere karşı yetersiz kalabileceğini gösterir. Bu durum, mimarların güvenlik algoritmalarını ve uygulamalarını periyodik olarak gözden geçirmeleri ve güncellemeleri gerektiğini vurgular. Kriptografik algoritmaların güvenliği zamanla değişir. Daha güçlü donanımlar (özellikle GPU'lar), eskiden güvenli kabul edilen algoritmaları kırmayı kolaylaştırır. PBKDF2'nin yüksek iterasyon sayısına rağmen Argon2 ve BCrypt'e göre daha zayıf kalması, bu evrimin bir sonucudur. Bu durum, mimarın sadece mevcut en iyi uygulamaları bilmekle kalmayıp, aynı zamanda güvenlik alanındaki gelişmeleri sürekli takip etmesi ve uygulamalarını buna göre adapte etmesi gerektiğini gösterir.   

**Parola Hashleme Algoritmalarının Karşılaştırması**

![image](https://github.com/user-attachments/assets/7e0c876f-3799-4053-9fcb-4def7c380989)

**PKI (Public Key Infrastructure) ve X.509 Sertifikaları**

Genel anahtarların sahiplerine güvenli bir şekilde bağlanmasını sağlayan bir sistemdir. X.509 sertifikaları, bir genel anahtarı bir varlığa (kullanıcı, bilgisayar, hizmet) bağlayan dijital belgelerdir ve bir Sertifika Otoritesi (CA) tarafından dijital olarak imzalanır.

**Dijital Sertifikaların Rolü ve Kullanımı:** Kimlik doğrulama, veri bütünlüğü ve gizlilik sağlamak için kullanılır.

**Dijital İmzalar:** Bir verinin bütünlüğünü ve kaynağını doğrulamak için kullanılır. Verinin hash'i gönderenin özel anahtarıyla şifrelenir. Dijital imzaların sadece verinin bütünlüğünü değil, aynı zamanda "inkar edilemezlik" (non-repudiation) özelliğini de sağlaması , bir işlemin veya belgenin kaynağının sonradan inkar edilememesini garanti eder. Bu, yasal geçerliliği olan veya yüksek güven gerektiren sistemlerde (örneğin finans, sağlık) kritik bir güvenlik özelliğidir. Bir dijital imza, bir kişinin fiziksel imzasının dijital eşdeğeridir. Özel anahtarla imzalanan veri, sadece o özel anahtarın sahibi tarafından imzalanmış olabilir. Genel anahtar ile bu imzanın doğrulanması, hem verinin değişmediğini (bütünlük) hem de belirli bir kişi tarafından imzalandığını (kimlik doğrulama ve inkar edilemezlik) kanıtlar. Bu durum, özellikle denetlenebilirlik ve hesap verebilirlik açısından önemlidir.   

**X.509 Sertifikası ile Veri İmzalama ve Doğrulama (RSA)**

```csharp
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public class DigitalSignatureManager
{
    /// <summary>
    /// Verilen mesajı X.509 sertifikasının özel anahtarını kullanarak imzalar.
    /// </summary>
    /// <param name="certificate">Özel anahtarı içeren X.509 sertifikası.</param>
    /// <param name="message">İmzalanacak mesaj.</param>
    /// <param name="hashAlgorithm">Kullanılacak hash algoritması (örn. HashAlgorithmName.SHA256).</param>
    /// <returns>Base64 kodlu dijital imza.</returns>
    public static string SignMessage(X509Certificate2 certificate, string message, HashAlgorithmName hashAlgorithm)
    {
        if (!certificate.HasPrivateKey)
        {
            throw new CryptographicException("Certificate does not contain a private key for signing.");
        }

        using (RSA rsa = certificate.GetRSAPrivateKey())
        {
            byte data = Encoding.UTF8.GetBytes(message);
            byte signature = rsa.SignData(data, hashAlgorithm, RSASignaturePadding.Pkcs1);
            return Convert.ToBase64String(signature);
        }
    }

    /// <summary>
    /// Verilen mesajın dijital imzasını X.509 sertifikasının genel anahtarını kullanarak doğrular.
    /// </summary>
    /// <param name="certificate">Genel anahtarı içeren X.509 sertifikası.</param>
    /// <param name="message">Doğrulanacak orijinal mesaj.</param>
    /// <param name="signatureBase64">Base64 kodlu dijital imza.</param>
    /// <param name="hashAlgorithm">Kullanılan hash algoritması (örn. HashAlgorithmName.SHA256).</param>
    /// <returns>İmza geçerliyse true, aksi takdirde false.</returns>
    public static bool VerifyMessage(X509Certificate2 certificate, string message, string signatureBase64, HashAlgorithmName hashAlgorithm)
    {
        using (RSA rsa = certificate.GetRSAPublicKey())
        {
            byte data = Encoding.UTF8.GetBytes(message);
            byte signature = Convert.FromBase64String(signatureBase64);
            return rsa.VerifyData(data, signature, hashAlgorithm, RSASignaturePadding.Pkcs1);
        }
    }

    /// <summary>
    /// Bir sertifika deposundan sertifika alır.
    /// </summary>
    /// <param name="certSubjectName">Sertifikanın konu adı (örn. "CN=MyTestCert").</param>
    /// <param name="storeLocation">Sertifika deposu konumu (örn. StoreLocation.CurrentUser).</param>
    /// <returns>Bulunan X509Certificate2 nesnesi veya null.</returns>
    public static X509Certificate2 GetCertificateFromStore(string certSubjectName, StoreLocation storeLocation = StoreLocation.CurrentUser)
    {
        X509Store store = new X509Store(storeLocation);
        try
        {
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certCollection = store.Certificates.Find(
                X509FindType.FindBySubjectName, certSubjectName, false); // false: Geçerli olmayanları da dahil et

            if (certCollection.Count > 0)
            {
                // Genellikle en güncel veya en uygun sertifikayı seçmek gerekebilir
                return certCollection; 
            }
            return null;
        }
        finally
        {
            store.Close();
        }
    }
}
// Kullanım örneği:
// string testMessage = "Bu bir test mesajıdır.";
// X509Certificate2 signingCert = DigitalSignatureManager.GetCertificateFromStore("CN=CERT_SIGN_TEST_CERT", StoreLocation.CurrentUser);

// if (signingCert!= null)
// {
//     string digitalSignature = DigitalSignatureManager.SignMessage(signingCert, testMessage, HashAlgorithmName.SHA256);
//     Console.WriteLine($"Dijital İmza: {digitalSignature}");

//     bool isSignatureValid = DigitalSignatureManager.VerifyMessage(signingCert, testMessage, digitalSignature, HashAlgorithmName.SHA256);
//     Console.WriteLine($"İmza Geçerli mi: {isSignatureValid}");
// }
// else
// {
//     Console.WriteLine("İmzalama sertifikası bulunamadı.");
//     // Makecert.exe ile test sertifikası oluşturma örneği [28, 75]:
//     // makecert -r -pe -n "CN=CERT_SIGN_TEST_CERT" -ss My -sr CurrentUser -a sha256 -cy end -sky signature -sv CERT_SIGN_TEST_CERT.pvk CERT_SIGN_TEST_CERT.cer
//     // pvk2pfx -pvk CERT_SIGN_TEST_CERT.pvk -spc CERT_SIGN_TEST_CERT.cer -pfx CERT_SIGN_TEST_CERT.pfx
// }
```

---

## 🏗️ Tedarik Zinciri Güvenliği

Yazılım tedarik zinciri güvenliği, uygulamanın kendi kodunun ötesinde, kullanılan tüm üçüncü taraf bileşenlerin ve bağımlılıkların güvenliğini kapsar.

**NuGet Bağımlılıkları:** 

Uygulamaların %90'a varan kısmının açık kaynak bağımlılıklarından oluşması yaygındır. Bu durum, yazılım güvenliğinin sadece kendi kodunuzla sınırlı olmadığını gösterir. 

- Güvenli Paket Kaynakları: Sadece güvenilir paket kaynaklarını kullanın. NuGet, HTTPS kullanımını zorunlu kılarak iletim sırasında güvenliği sağlar.
- Zafiyet Taraması: Bağımlılıkları bilinen zafiyetler (CVE'ler) için düzenli olarak tarayın. NuGet, zafiyet bildirimleri sunar.
- Paket İmzalama ve Doğrulama: Paket imzalarını doğrulayarak paketin güvenilir bir kaynaktan geldiğinden ve kurcalanmadığından emin olun.
- NuGet'in "Package ID Prefix Reservations" ve "2FA Required for Publishers" gibi özellikleri , ekosistem düzeyinde tedarik zinciri saldırılarını (örneğin, typosquatting, hesap ele geçirme) önlemeye yönelik proaktif adımlardır. Bu durum, sadece son kullanıcının değil, paket yöneticilerinin de güvenliğe katkıda bulunması gerektiğini gösterir. Tedarik zinciri saldırıları, bir uygulamanın kendi kodunda zafiyet olmasa bile, kullanılan bir bağımlılık üzerinden sisteme sızmayı hedefler (SolarWinds örneği). NuGet'in bu tür saldırılara karşı aldığı önlemler, ekosistemin genel güvenliğini artırır. Bir mimar olarak, kullanılan paketlerin sadece işlevsel değil, aynı zamanda güvenli olduğundan emin olmak için bu tür platform özelliklerini kullanmalı ve bağımlılıklarını düzenli olarak denetlemelidir.   

**SBOM (Software Bill of Materials):** 

Uygulamanızdaki tüm yazılım bileşenlerinin (kendi kodunuz, açık kaynak kütüphaneleri, ticari ürünler) eksiksiz bir envanteridir. SBOM, bilinen zafiyetleri hızlıca tespit etmeye ve yasal uyumluluğu sağlamaya yardımcı olur.   

**Üçüncü Taraf Bileşenlerin Güvenliği:** 

Popülerlik, dokümantasyon kalitesi, aktif bakım ve güvenlik pratikleri gibi kriterlere göre açık kaynak bağımlılıklarını seçin. Otomatik güncellemeleri destekleyen bağımlılıkları tercih edin. Bir bağımlılığın popülerliği, güvenilirliğinin bir göstergesi olabilir çünkü daha fazla kullanıcı ve katkıcı, zafiyetlerin daha hızlı tespit edilip düzeltilmesine yol açar. Ancak bu tek başına yeterli değildir; aktif bakım ve güvenlik pratikleri de göz önünde bulundurulmalıdır. Popülerlik, bir projenin geniş bir topluluk tarafından incelendiği ve test edildiği anlamına gelebilir, bu da güvenlik açıklarının daha hızlı bulunup kapatılmasına yardımcı olabilir. Ancak, popüler ancak bakımı yapılmayan bir proje, yeni zafiyetlere karşı savunmasız kalabilir. Bu nedenle, mimar bağımlılık seçiminde hem popülerliği hem de aktif güvenlik pratiklerini bir arada değerlendirmelidir.   

---

## ☁️ Bulut ve Konteyner Güvenliği

Bulut tabanlı ve konteynerize edilmiş uygulamaların kendine özgü güvenlik zorlukları ve en iyi uygulamaları vardır.

**Bulut Güvenliği (Azure/AWS)**

- **Paylaşılan Sorumluluk Modeli:** AWS gibi bulut sağlayıcıları "bulutun güvenliğinden" (fiziksel altyapı, ağ, donanım) sorumluyken, müşteri "buluttaki güvenlikten" (uygulamalar, veriler, yapılandırmalar, kimlik ve erişim yönetimi) sorumludur. Azure'da da benzer bir model mevcuttur.
- **Kimlik ve Erişim Yönetimi (IAM):** En az ayrıcalık prensibini uygulayın. Çok Faktörlü Kimlik Doğrulamayı (MFA) zorunlu kılın. Azure RBAC veya AWS IAM ile rol tabanlı erişim kontrolü uygulayın. Azure PIM (Privileged Identity Management) ile Just-in-Time (JIT) erişim sağlayın.
- **Ağ Güvenliği:** Ağ güvenlik grupları (NSG'ler) ile trafiği filtreleyin (Azure). Azure Firewall veya AWS WAF gibi güvenlik duvarlarını kullanın. Ağ segmentasyonu uygulayın.
- **Veri Koruma:** Veriyi hem "at rest" (depoda) hem de "in transit" (aktarımda) şifreleyin. Azure Key Vault veya AWS KMS gibi anahtar yönetim çözümlerini kullanın. Hassas bilgileri kodda hardcode etmekten kaçının.
- **İzleme ve Tehdit Tespiti:** Azure Monitor, Microsoft Sentinel veya AWS Security Hub, GuardDuty gibi araçlarla sürekli izleme ve günlük analizi yapın.

Bulut ortamlarında "assume breach" (ihlali varsay) yaklaşımının benimsenmesi , güvenlik stratejisinin sadece önlemeye değil, aynı zamanda tespit ve yanıt yeteneklerine de odaklanması gerektiğini gösterir. Bu durum, bulutun dinamik ve genişleyen saldırı yüzeyine karşı daha gerçekçi bir duruş sergiler. Bulut ortamları, geleneksel şirket içi (on-premise) altyapılardan çok daha dinamiktir ve sürekli değişir. Bu durum, ihlallerin kaçınılmaz olabileceği bir zihniyetle yaklaşmayı gerektirir. "Assume breach" yaklaşımı, bir ihlal meydana geldiğinde ne yapacağınızı (tespit, yanıt, kurtarma) önceden planlamanızı sağlar ve bu da hasarı minimize etmeye yardımcı olur.   

**Konteyner Güvenliği (Docker/Kubernetes)**

- **Güvenli İmajlar:** Güvenilir ve minimal taban imajları kullanın (Alpine, distroless). Çok aşamalı derlemeler (multi-stage builds) ile son imaj boyutunu küçültün. İmajları bilinen zafiyetler için tarayın (Trivy, Clair, Docker Hub taraması). İmajları düzenli olarak yeniden oluşturun ve güncel tutun.
- **En Az Ayrıcalık:** Konteynerleri kök olmayan bir kullanıcı olarak çalıştırın. Gereksiz Linux yeteneklerini (--cap-drop all) bırakın ve sadece gerekli olanları ekleyin (--cap-add CHOWN). --security-opt=no-new-privileges kullanarak ayrıcalık yükseltmeyi önleyin.
- **Kaynak Limitleri:** Bellek ve CPU limitleri belirleyerek hizmet reddi (DoS) saldırılarını önleyin.
- **Sır Yönetimi:** Hassas verileri (API anahtarları, kimlik bilgileri) imaja hardcode etmekten kaçının. Docker Secrets, Kubernetes Secrets veya harici sır yönetim araçları (Azure Key Vault, HashiCorp Vault, AWS Secrets Manager) kullanın.
- **Ağ Kısıtlamaları:** Konteynerler arası iletişimi kısıtlayın ve özel Docker ağları kullanın. Güvenlik duvarları uygulayın.
- **Güncel Tutma:** Host ve Docker/Kubernetes ortamını düzenli olarak güncelleyin.   

Konteyner güvenliğinin, hem derleme zamanı (güvenli imajlar, çok aşamalı derlemeler) hem de çalışma zamanı (en az ayrıcalık, kaynak limitleri, sır yönetimi) kontrollerini gerektirmesi, DevSecOps'un "shift left" prensibinin konteynerleştirilmiş uygulamalar için de geçerli olduğunu gösterir. Güvenlik, Dockerfile'dan dağıtım ortamına kadar her aşamada düşünülmelidir. Konteynerler, uygulamaları dağıtmayı kolaylaştırsa da, yeni güvenlik katmanları ve riskler getirir. Bir imajın derleme aşamasında zafiyetli bileşenler veya hardcoded sırlar içermesi, çalışma zamanında ciddi riskler oluşturur. Bu nedenle, güvenlik kontrolleri sadece çalışan konteynerleri değil, aynı zamanda onların oluşturulduğu imajları ve üzerinde çalıştıkları host sistemleri de hedef almalıdır.

---

## 🛠️ DevSecOps ve CI/CD Süreçleri

DevSecOps, güvenliği yazılım geliştirme yaşam döngüsünün (SDLC) her aşamasına entegre eden bir yaklaşımdır.

**Shift Left Prensibi:**

Güvenlik kontrollerini geliştirme sürecinin mümkün olduğunca erken aşamalarına taşımak. Bu, zafiyetleri erken tespit ederek düzeltme maliyetini ve çabasını azaltır. DevSecOps'un sadece güvenlik açıklarını erken bulmakla kalmayıp, aynı zamanda yazılım kalitesini %60 artırması ve pazara çıkış süresini %20 kısaltması , güvenliğin bir engelleyici değil, aksine geliştirme sürecini hızlandıran ve iyileştiren bir faktör olduğunu gösterir. Bu durum, güvenlik ve hız arasında bir denge değil, bir sinerji olduğunun açık bir kanıtıdır. Geleneksel güvenlik yaklaşımlarında güvenlik, geliştirmenin sonuna bırakılan bir "engel" olarak görülürdü. Ancak DevSecOps, güvenliği geliştirme sürecine entegre ederek, hataların erken aşamada, yani düzeltilmesi en ucuz olduğu zamanda bulunmasını sağlar. Bu da daha az yeniden çalışma, daha hızlı dağıtım ve daha yüksek kaliteli yazılım anlamına gelir.

**CI/CD Entegrasyonu:**

- **Sürekli Entegrasyon (CI) ve Sürekli Dağıtım (CD):** Kod değişikliklerinin otomatik olarak entegre edilmesi ve dağıtılması. Güvenlik kontrolleri CI/CD hattına dahil edilmelidir.
- **Otomatik Güvenlik Testleri:** SAST, DAST, SCA gibi araçları CI/CD pipeline'ına entegre edin. GitHub Actions gibi araçlar bu entegrasyonu kolaylaştırır.
- **Sır Taraması (Secret Scanning):** Kod depolarında (Azure Repos, GitHub) açıkta kalmış sırları (API anahtarları, kimlik bilgileri) tespit edin ve yeni sırların kodla birlikte dağıtılmasını önleyin.
- **Bağımlılık Taraması (Dependency Scanning):** Kullanılan açık kaynak bileşenlerdeki zafiyetleri tespit edin ve düzeltme yönergeleri alın.
- **Kod Güvenliği Taraması (Code Security Scanning):** Statik analiz araçları (CodeQL) ile kodunuzdaki derin güvenlik zafiyetlerini bulun ve düzeltin.   

GitHub Advanced Security'nin (GHAS) Azure DevOps ile entegrasyonu , Microsoft'un kendi ekosisteminde "güvenliği geliştirici iş akışına doğal olarak entegre etme" stratejisini yansıtır. Bu durum,.NET mimarları için güvenlik araçlarının ve süreçlerinin daha erişilebilir ve kullanışlı hale geldiğini gösterir. Büyük platform sağlayıcıları (Microsoft, GitHub) güvenlik özelliklerini kendi araçlarına ve platformlarına entegre ederek DevSecOps'u daha kolay uygulanabilir hale getirir. Bu durum, geliştiricilerin güvenlik kontrollerini ayrı bir adım olarak değil, doğal bir iş akışı parçası olarak görmesini sağlar. Bir.NET mimarı olarak, bu entegre araçlardan faydalanmak, güvenlik süreçlerinin benimsenmesini hızlandırır ve manuel çabayı azaltır.   

---

## 🧪 Güvenlik Testleri ve Tarama Araçları

Uygulama güvenliğini sağlamak için çeşitli test ve analiz teknikleri kullanılır.

- **SAST (Static Application Security Testing - Statik Uygulama Güvenlik Testi):** Uygulama kodunu çalıştırmadan analiz eder (kaynak kodu, byte kodu veya ikili kod). Geliştirme aşamasında hataları erken tespit etmeye yardımcı olur. SQL enjeksiyonları veya XSS gibi bilinen zafiyetleri bulabilir.
- **DAST (Dynamic Application Security Testing - Dinamik Uygulama Güvenlik Testi):** Uygulama çalışırken test eder, gerçek saldırıları simüle ederek canlı ortamdaki zafiyetleri tespit eder.
- **IAST (Interactive Application Security Testing - Etkileşimli Uygulama Güvenlik Testi):** SAST ve DAST'ın unsurlarını birleştirir. Test ortamında ajanlar olarak çalışır ve uygulama davranışını gözlemleyerek sorunları gerçek zamanlı olarak raporlar.
- **SCA (Software Composition Analysis - Yazılım Bileşimi Analizi):** Üçüncü taraf kütüphanelerdeki ve açık kaynak bileşenlerdeki bilinen zafiyetleri tarar.   

**SAST, DAST, IAST, SCA Araçlarının Karşılaştırması**

![image](https://github.com/user-attachments/assets/653632db-eaea-4785-86d1-51c3ea978442)

**Penetrasyon Testleri (Penetration Testing - Pen Test):** 

Güvenlik profesyonellerinin bir sistemdeki zafiyetleri bulmak ve istismar etmek için gerçek dünya saldırılarını simüle ettiği bir testtir. Bilgi toplama, araştırma ve istismar, raporlama ve öneriler, düzeltme ve sürekli destek adımlarını içerir.   

**Zafiyet Değerlendirmesi (Vulnerability Assessment):** 

Sistemlerdeki güvenlik zafiyetlerini tanımlama, nicelendirme, analiz etme ve önceden tanımlanmış risklere göre bu zafiyetleri giderme sürecidir. Kapsam belirleme, saldırı yüzeyini haritalama, zafiyet analizi, tehdit ve risk değerlendirmesi, düzeltme ve yeniden test etme adımlarını içerir.   

**Güvenli Kod İncelemesi (Secure Code Review):**

Yazılım uygulamalarının kaynak kodunu güvenlik açıklarını ortaya çıkarmak için inceleme işlemidir. Manuel veya otomatik araçlarla yapılabilir. Girdi doğrulama, kimlik doğrulama ve kullanıcı yönetimi, yetkilendirme, oturum yönetimi, şifreleme ve kriptografi, istisna işleme gibi alanları kapsayan kontrol listeleri kullanılır.

---

## 🚨 Saldırı Tespit ve Önleme Sistemleri

Siber güvenlik savunmasının önemli bir parçası olan bu sistemler, ağ ve uygulama seviyesinde tehditleri belirleyip engellemek için tasarlanmıştır.

- **IDS (Intrusion Detection System - Saldırı Tespit Sistemi):** Ağ trafiğindeki şüpheli faaliyetleri arayan ve şüpheli etkinlik tespit ettiğinde uyarı gönderen sistemlerdir. Pasif olarak çalışır, yani trafiği izler ancak engellemez.
- **IPS (Intrusion Prevention System - Saldırı Önleme Sistemi):** Ağdaki stratejik noktalarda kötü niyetli etkinliği tarayan ve yapılandırıldığı şekilde kötü niyetli trafiği raporlayan, engelleyen veya düşüren bir ağ güvenlik cihazıdır. Genellikle bir güvenlik duvarının arkasına ve WAF'tan önce konuşlandırılır. IDS'in aksine, aktif olarak tehditleri önler.
- **WAF (Web Uygulama Güvenlik Duvarları - Web Application Firewall):** Web'e bakan uygulamaların önüne yerleştirilen ve SQL enjeksiyonu, XSS gibi kötü niyetli saldırılara karşı koruma sağlayan bir donanım, sanal cihaz veya bulut tabanlı hizmettir. HTTP trafiğini uygulama sunucusuna ulaşmadan önce inceler ve filtreler. WAF'lar, IPS'i tamamlar ve genellikle birlikte kullanılır.   

---

## 🧠 Tehdit Modelleme ve Güvenlik Analizi

Tehdit modelleme, bir uygulamanın veya sistemin potansiyel tehditlerini, saldırılarını, zafiyetlerini ve karşı önlemlerini belirlemek için kullanılan mühendislik tekniğidir.   

**Tehdit Modelleme Metodolojileri**

**STRIDE:** 

Microsoft tarafından geliştirilmiştir. Tasarım sürecinde bir ürünün hangi tehdit türlerine karşı hassas olduğunu belirlemeyi amaçlar

- **Spoofing (Kimlik Sahteciliği):** Kimlik doğrulamanın atlatılması.
- **Tampering (Kurcalama):** Yetkisiz veri değişikliği.
- **Repudiation (İnkar):** Bir eylemi inkar etme yeteneği.
- **Information Disclosure (Bilgi İfşası):** Yetkisiz taraflara bilgi sızdırma.
- **Denial of Service (Hizmet Reddi):** Sistemi kullanılamaz hale getirme.
- **Elevation of Privilege (Ayrıcalık Yükseltme):** Yetkisiz sistem ve kaynaklara erişmek için ayrıcalıkları yükseltme.   

**PASTA (Process for Attack Simulation and Threat Analysis):**

Saldırgan odaklı, risk merkezli bir metodolojidir. Yönetim, operasyonlar, mimari ve geliştirmeden girdi alarak tehdit analizini stratejik bir bakış açısıyla gerçekleştirir. Yedi aşamalı bir süreçtir.   

**DREAD:** 

Esas olarak tehditlerin ciddiyetini ölçmek ve sıralamak için kullanılır. Genellikle STRIDE ile birlikte kullanılır; STRIDE tehditleri tanımlarken, DREAD ciddiyetini sıralar.   

- **Damage potential (Hasar potansiyeli):** Tehdidin neden olabileceği maksimum hasar miktarı.
- **Reproducibility (Tekrarlanabilirlik):** Bir saldırının ne kadar zor tekrarlanabileceği.
- **Exploitability (İstismar edilebilirlik):** Bir saldırı için gereken beceri, enerji ve kaynaklar.
- **Affected users (Etkilenen kullanıcılar):** Etkilenecek kullanıcı yüzdesi.
-** Discoverability (Keşfedilebilirlik):** Saldırganın tehdidi keşfetme olasılığı.   

**Tehdit Modelleme Metodolojileri Karşılaştırması**

![image](https://github.com/user-attachments/assets/5615b73c-e7b4-4ba2-85a9-d991079e24be)

Güvenlik Analizi Teknikleri

**Risk Değerlendirmesi:** Varlıkların tanımlanması, tehditlerin belirlenmesi ve zafiyetlerin analiz edilerek her tehdidin iş üzerindeki potansiyel etkisi ve olasılığının değerlendirilmesi.   

**Saldırı Yüzeyi Haritalama:** Bir uygulamanın veya sistemin saldırganlar tarafından istismar edilebilecek tüm potansiyel giriş noktalarını ve zayıf noktalarını belirleme.   

---

## 📜 Politikalar, Protokoller ve Tanımlamalar

Uygulama güvenliği, belirli politikalar, protokoller ve standart tanımlamalar aracılığıyla yönetilir.

**CVE (Common Vulnerabilities and Exposures - Ortak Zafiyetler ve Açıklıklar):** 

Yazılım ve donanımdaki bilinen güvenlik zafiyetlerini sınıflandıran ve benzersiz tanımlayıcılar atayan bir sözlüktür. Güvenlik danışmanlıkları, zafiyet veritabanları ve hata takip sistemleri bu standardı kullanır.   

**CVSS (Common Vulnerability Scoring System - Ortak Zafiyet Puanlama Sistemi):** 

Bir zafiyetin ciddiyetini 0-10 arası bir ölçekte değerlendirmek ve puanlamak için kullanılan standartlaştırılmış bir çerçevedir. Daha yüksek puanlar, daha ciddi zafiyetleri gösterir ve kuruluşların en kritik tehditlere odaklanmasına yardımcı olur.   

**Uygulama Güvenliği Politikaları ve Güvenli Kodlama Prensipleri:**

- **Girdi Doğrulama (Input Validation):** Tüm kullanıcı girdilerini güvenilmez kabul edin ve işlenmeden önce doğrulayın ve sanitize edin.
- **Güçlü Kimlik Doğrulama ve Yetkilendirme:** Çok faktörlü kimlik doğrulama (MFA) kullanın ve en az ayrıcalık prensibini uygulayın.
- **Güvenli Parola İşleme:** Parolaları asla düz metin olarak saklamayın; BCrypt veya Argon2 gibi güçlü, tuzlanmış hash algoritmaları kullanın.
- **Hata İşleme ve Günlükleme:** Kullanıcılara hassas bilgiler (stack trace gibi) içeren detaylı hata mesajları göstermekten kaçının. Tüm güvenlik olaylarını (başarısız girişler, yetkilendirme hataları) güvenli bir şekilde loglayın ve loglarda hassas veri tutmaktan kaçının.
- **Güvenli Bağımlılıklar ve Kütüphaneler:** Üçüncü taraf kütüphaneleri ve açık kaynak bileşenleri düzenli olarak güncelleyin ve zafiyetler için tarayın.
- **Güvenlik Başlıkları (Security Headers):** XSS saldırılarını önlemek için Content Security Policy (CSP) ve HTTPS kullanımını zorunlu kılmak için Strict-Transport-Security (HSTS) gibi güvenlik başlıklarını uygulayın.
- **Düzenli Güvenlik Testleri:** SAST, DAST ve penetrasyon testleri gibi güvenlik testlerini düzenli olarak yapın.

---
