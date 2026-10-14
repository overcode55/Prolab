// This acts as your server environment
export async function onRequest(context) {
    // Mock data to return from your "server"
    const data = {
        status: "success",
        message: "Hello from your Cloudflare Pages Server!",
        project: "School Concept Demo",
        timestamp: new Date().toISOString()
    };

    return new Response(JSON.stringify(data), {
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*" // Prevents CORS errors during testing
        }
    });
}
export async function onRequestPost(context) {
    const { email, username } = await context.request.json();
    
    // Create a unique key for the user, like "user:john@gmail.com"
    const userKey = `user:${email}`;
    
    // Save it directly into Cloudflare's free KV database
    await context.env.MY_USER_DB.put(userKey, JSON.stringify({
        username: username,
        email: email,
        createdAt: new Date().toISOString()
    }));

    return new Response(JSON.stringify({ success: true, message: "Account created!" }));
}