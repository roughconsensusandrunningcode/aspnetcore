// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Security.Claims;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.EntityFrameworkCore;

namespace TodoApi;

internal static class TodoApi
{
    private static string GetOwnerId(this ClaimsPrincipal user)
        => user.FindFirstValue(ClaimTypes.NameIdentifier)!;

    private static bool IsAdmin(this ClaimsPrincipal user)
        => user.IsInRole("admin");

    public static RouteGroupBuilder MapTodos(this IEndpointRouteBuilder routes)
    {
        var group = routes.MapGroup("/todos");

        group.WithTags("Todos");

        // Add security requirements, all incoming requests to this API *must*
        // be authenticated with a valid user.
        group.RequireAuthorization(/*pb => pb.RequireCurrentUser()*/)
             .AddOpenApiSecurityRequirement();

        // Rate limit all of the APIs
        //group.RequirePerUserRateLimit();

        // Validate the parameters
        //group.WithParameterValidation(typeof(TodoItem));

        group.MapGet("/", async (TodoDbContext db, HttpContext request) =>
        {
            return await db.Todos.Where(todo => todo.OwnerId == request.User.GetOwnerId()).Select(t => t.AsTodoItem()).AsNoTracking().ToListAsync();
        });

        group.MapGet("/{id}", async Task<Results<Ok<TodoItem>, NotFound>> (TodoDbContext db, int id, HttpContext request) =>
        {
            var owner = request.User;
            return await db.Todos.FindAsync(id) switch
            {
                Todo todo when (todo.OwnerId == owner.GetOwnerId() || owner.IsAdmin()) => TypedResults.Ok(todo.AsTodoItem()),
                _ => TypedResults.NotFound()
            };
        });

        group.MapPost("/", async Task<Created<TodoItem>> (TodoDbContext db, TodoItem newTodo, HttpContext request) =>
        {
            var todo = new Todo
            {
                Title = newTodo.Title,
                OwnerId = request.User.GetOwnerId()
            };

            db.Todos.Add(todo);
            await db.SaveChangesAsync();

            return TypedResults.Created($"/todos/{todo.Id}", todo.AsTodoItem());
        });

        group.MapPut("/{id}", async Task<Results<Ok, NotFound, BadRequest>> (TodoDbContext db, int id, TodoItem todo, HttpContext request) =>
        {
            if (id != todo.Id)
            {
                return TypedResults.BadRequest();
            }

            var owner = request.User;
            var rowsAffected = await db.Todos.Where(t => t.Id == id && (t.OwnerId == owner.GetOwnerId() || owner.IsAdmin()))
                                             .ExecuteUpdateAsync(updates =>
                                                updates.SetProperty(t => t.IsComplete, todo.IsComplete)
                                                       .SetProperty(t => t.Title, todo.Title));

            return rowsAffected == 0 ? TypedResults.NotFound() : TypedResults.Ok();
        });

        group.MapDelete("/{id}", async Task<Results<NotFound, Ok>> (TodoDbContext db, int id, HttpContext request) =>
        {
            var owner = request.User;
            var rowsAffected = await db.Todos.Where(t => t.Id == id && (t.OwnerId == owner.GetOwnerId() || owner.IsAdmin()))
                                             .ExecuteDeleteAsync();

            return rowsAffected == 0 ? TypedResults.NotFound() : TypedResults.Ok();
        });

        return group;
    }
}