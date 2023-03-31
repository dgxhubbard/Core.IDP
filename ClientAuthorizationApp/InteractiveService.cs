using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using OpenIddict.Client;
using static OpenIddict.Abstractions.OpenIddictConstants;
using static OpenIddict.Abstractions.OpenIddictExceptions;

namespace ClientApp;

public class InteractiveService : BackgroundService
{
    private readonly IHostApplicationLifetime _lifetime;
    private readonly OpenIddictClientService _service;

    public InteractiveService(
        IHostApplicationLifetime lifetime,
        OpenIddictClientService service)
    {
        _lifetime = lifetime;
        _service = service;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait for the host to confirm that the application has started.
        var source = new TaskCompletionSource<bool>();
        using (_lifetime.ApplicationStarted.Register(static state => ((TaskCompletionSource<bool>) state!).SetResult(true), source))
        {
            await source.Task;
        }

        Console.WriteLine("Press any key to start the authentication process.");
        await Task.Run(Console.ReadKey).WaitAsync(stoppingToken);

        string token = null;
        try
        {
            // Ask OpenIddict to initiate the authentication flow (typically, by
            // starting the system browser) and wait for the user to complete it.
            var (_, response, _) = await _service.AuthenticateInteractivelyAsync (
                provider: "Local",
                cancellationToken: stoppingToken );

            token = response.AccessToken;

        }

        catch (OperationCanceledException)
        {
            Console.WriteLine("The authentication process was aborted.");
        }

        catch (ProtocolException exception) when (exception.Error is Errors.AccessDenied)
        {
            Console.WriteLine("The authorization was denied by the end user.");
        }

        catch
        {
            Console.WriteLine("An error occurred while trying to authenticate the user.");
        }

    }
}
