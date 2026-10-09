import { useEffect, useState } from "react";
import { type Digest, fetchDigest } from "./api";
import { FlagItem } from "./FlagItem";

export function Inbox() {
  const [digest, setDigest] = useState<Digest>();
  const [error, setError] = useState<string>();

  useEffect(() => {
    fetchDigest().then(setDigest, (e: Error) => setError(e.message));
  }, []);

  if (error) return <p className="error">Couldn't load the digest: {error}</p>;
  if (!digest) return <p>Loading…</p>;
  const { actions, captured, need_review } = digest.headline;
  return (
    <main>
      <h1>{`${actions} actions · ${captured} captured · ${need_review} need review`}</h1>
      {need_review === 0 && <p>Nothing needs review.</p>}
      {digest.projects.map(({ project, sessions }) => (
        <section key={project ?? ""}>
          <h2>{project ?? "No project"}</h2>
          {sessions.map(({ session_id, flags }) => (
            <section key={session_id ?? ""}>
              <h3>{`Session ${session_id?.slice(0, 8) ?? "unknown"}`}</h3>
              <ul className="flags">
                {flags.map((flag) => (
                  <FlagItem key={flag.id} flag={flag} />
                ))}
              </ul>
            </section>
          ))}
        </section>
      ))}
    </main>
  );
}
