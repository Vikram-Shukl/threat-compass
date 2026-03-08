import { supabase } from "@/integrations/supabase/client";

export async function fetchThreatFox(body: Record<string, unknown>): Promise<any> {
  const { data, error } = await supabase.functions.invoke("threatfox-proxy", {
    body,
  });

  if (error) throw new Error("Failed to fetch threat data: " + error.message);
  return data;
}
