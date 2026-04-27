import { corsHeaders } from "@supabase/supabase-js/cors";

interface GeoResult {
  ip: string;
  lat: number;
  lng: number;
  country: string;
  countryCode: string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  try {
    if (req.method !== "POST") {
      return new Response(JSON.stringify({ error: "Method not allowed" }), {
        status: 405,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      });
    }

    const body = await req.json().catch(() => null);
    if (!body || !Array.isArray(body.ips)) {
      return new Response(
        JSON.stringify({ error: "Body must be { ips: string[] }" }),
        {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" },
        }
      );
    }

    const ips: string[] = body.ips
      .filter((x: unknown) => typeof x === "string")
      .slice(0, 10);

    const results: GeoResult[] = [];
    for (const ip of ips) {
      try {
        const res = await fetch(`https://ipapi.co/${ip}/json/`);
        const r = await res.json();
        if (r.latitude && r.longitude) {
          results.push({
            ip,
            lat: r.latitude,
            lng: r.longitude,
            country: r.country_name ?? "",
            countryCode: r.country_code ?? "",
          });
        }
      } catch {
        // skip failures
      }
      await new Promise((resolve) => setTimeout(resolve, 300));
    }

    return new Response(JSON.stringify({ results }), {
      status: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: (err as Error).message ?? "Unknown error" }),
      {
        status: 500,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
      }
    );
  }
});
