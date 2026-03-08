import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await req.json();
    const authKey = Deno.env.get("THREATFOX_AUTH_KEY");

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (authKey) {
      headers["Auth-Key"] = authKey;
    }

    const res = await fetch("https://threatfox-api.abuse.ch/api/v1/", {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });

    const data = await res.text();

    return new Response(data, {
      status: 200,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json",
      },
    });
  } catch (error) {
    return new Response(
      JSON.stringify({ error: error.message }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
