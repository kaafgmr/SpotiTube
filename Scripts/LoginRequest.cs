using System.Collections.Generic;
using System.Net;
using System.IO;
using System;
using Godot;

public partial class LoginRequest : Control
{

    [Export]
    private string clientId;

    [Export]
    private string clientSecret;

    private const string httpsPrefix = "https://";
    private const string spotiUrl= "spotify.com/";
    private const string redirectUri = "http://localhost:3000/callback";
    private const string scopes = "user-library-read";
    private const string issuerName = "CN=owKaaf,O=KaafStudios,C=ES";
    private string codeVerifier = "";
    private string codeChallenge = "";
    private string token = null;

    private int randomStringSize = 128; //docs says that it has to be between 43 and 128 characters 

    private Crypto crypto = new Crypto();
    private CryptoKey key = new CryptoKey();

    private HttpListener listener;
    private HttpRequest tokenRequest;
    private HttpRequest userTrackRequest;

    [Signal]
    public delegate void UserAcceptedRequestEventHandler(string code);

	public override void _Ready()
	{
        CreateCredentialsIfNeeded();

        codeVerifier = GenerateRandomString(randomStringSize);
        byte[] hash = codeVerifier.Sha256Buffer();
        codeChallenge = Marshalls.RawToBase64(hash).TrimEnd('=').Replace('+','-').Replace('/', '_');

        UserAcceptedRequest += ExchangeCodeForToken;
        tokenRequest = new HttpRequest();
        AddChild(tokenRequest);
        tokenRequest.RequestCompleted += SetToken;

        userTrackRequest = new HttpRequest();
        AddChild(userTrackRequest);
        userTrackRequest.RequestCompleted += PrintUserTracks; 

        StartListeningUserLogin();

        RedirectUserForAuth();
	}

    private string GenerateRandomString(int length)
    {
        const string possibleValues = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        byte[] randomBytes = crypto.GenerateRandomBytes(length);
        string randomString = "";
        
        for (int i = 0; i < length; i++)
        {
           randomString += possibleValues[randomBytes[i] % possibleValues.Length];
        }

        return randomString;
    }

    private void CreateCredentialsIfNeeded()
    {

        const string keyPath = "user://generatedKey.key";
        const string certificatePath = "user://generatedCertificate.crt";

        Error err = key.Load(keyPath);

        if(err.Equals(Error.Ok))
        {
           return;
        }
        
        GD.PushWarning("Error trying to load key, creating a new one");

        key = crypto.GenerateRsa(4096);

        X509Certificate certificate = crypto.GenerateSelfSignedCertificate(key, issuerName);

        key.Save(keyPath);
        certificate.Save(certificatePath);
    }

    private void StartListeningUserLogin()
    {
        listener = new HttpListener();
        listener.Prefixes.Add(redirectUri + "/");
        listener.Start();
        listener.BeginGetContext(new AsyncCallback(OnUserLogin), listener);
    }

    private void RedirectUserForAuth()
    {
        const string paramResponseType = "response_type=code";
        string paramClientId = $"client_id={clientId}";
        string paramScope = $"scope={Uri.EscapeDataString(scopes)}";
        const string paramCodeChallengeMethod = "code_challenge_method=S256";
        string paramCodeChallenge = $"code_challenge={codeChallenge}";
        string paramRedirectUri = $"redirect_uri={Uri.EscapeDataString(redirectUri)}";

        string authUrl = $"{httpsPrefix}accounts.{spotiUrl}authorize?{paramResponseType}&{paramClientId}&{paramScope}&{paramCodeChallengeMethod}&{paramCodeChallenge}&{paramRedirectUri}";

        OS.ShellOpen(authUrl);
    }

    private void OnUserLogin(IAsyncResult result)
    {
        HttpListenerContext context = listener.EndGetContext(result);
        HttpListenerRequest request = context.Request;
        
        string err = request.QueryString["error"];

        if(!String.IsNullOrEmpty(err))
        {
            GD.PrintErr("Error on requesting user auth code: " + err); 
        }else {
            string code = request.QueryString["code"];

            CloseWindowUserFeedback(context.Response);

            if (!string.IsNullOrEmpty(code))
            {
                CallDeferred(MethodName.EmitSignal, SignalName.UserAcceptedRequest, code);
            }
        }

    }

    private void CloseWindowUserFeedback(HttpListenerResponse response)
    {
        const string responseString = "<html><body> You can close this window now </body></html>";
        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
        response.ContentLength64 = buffer.Length;
        Stream output = response.OutputStream;
        output.Write(buffer, 0, buffer.Length);
        output.Close();
    }

    private void ExchangeCodeForToken(string code)
    {
        string url = $"{httpsPrefix}accounts.{spotiUrl}api/token";

        Dictionary<string, string> dataToSend = new Dictionary<string, string>
        {
            {"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", redirectUri},
            {"client_id", clientId},
            {"code_verifier", codeVerifier}
        };

        string postData = "";
        foreach(KeyValuePair<string, string> data in dataToSend)
        {
            if(postData != "")
            {
                postData += "&";
            }
            postData += $"{Uri.EscapeDataString(data.Key)}={Uri.EscapeDataString(data.Value)}";
        }

        string[] headers = {"Content-Type: application/x-www-form-urlencoded"};

        Error err = tokenRequest.Request(url, headers, HttpClient.Method.Post, postData);
        if (!err.Equals(Error.Ok))
        {
            GD.PrintErr($"Error at requesting token: {err}");
        }
    }

    private void SetToken(long result, long response_code, string[] headers, byte[] body)
    {
        if(!result.Equals((long)HttpRequest.Result.Success))
        {
            GD.PrintErr("Could not get token, response code: " + response_code);
        }

        Json json = new Json();
        json.Parse(body.GetStringFromUtf8());

        if(json.Data.AsGodotDictionary() is Godot.Collections.Dictionary jsonResponse && jsonResponse.ContainsKey("access_token"))
        {
            token = jsonResponse["access_token"].ToString();

            FetchUserTracks();
        }
    }

    private void FetchUserTracks()
    {
        int limit = 20; // maximum is 50 per request
        int offset = 0;

        string url = $"{httpsPrefix}api.{spotiUrl}v1/me/tracks?limit={limit}&offset={offset}";
        string[] headers = {$"Authorization: Bearer {token}"}; 
        userTrackRequest.Request(url, headers, HttpClient.Method.Get);
    }

    private void PrintUserTracks(long result, long response_code, string[] headers, byte[] body)
    {
        if(result != (long)HttpRequest.Result.Success)
        {
            GD.PrintErr("Could not fetch user tracks. response code: " + response_code);
        }

        Json jsonData = new Json();
        jsonData.Parse(body.GetStringFromUtf8());

        Godot.Collections.Dictionary data = jsonData.Data.AsGodotDictionary();
        Godot.Collections.Array items = data["items"].AsGodotArray();

        GetTracksFromItemsArray(items);

        listener.Stop();
    }

    private Godot.Collections.Dictionary GetTracksFromItemsArray(Godot.Collections.Array items)
    {
        Godot.Collections.Dictionary tracks = new Godot.Collections.Dictionary();

        //each id in items is an array with [added_at, track_data]
        GD.Print(items[0].AsGodotDictionary()["track"]);

        /*
        for (int i = 0; i < items.Count; i++)
        {
            if(i%2 == 0)
            {
                GD.Print(items[i]);
            }
        }
        */
        return tracks;
    }
}
