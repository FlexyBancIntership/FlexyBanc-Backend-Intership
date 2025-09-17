{
  type: "registration",
  data: {
    identity: ctx.identity,
    session: if std.objectHas(ctx, 'session') then ctx.session else null
  }
}