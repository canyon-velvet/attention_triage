import type { Flag } from "./api";

// Everything here is captured from the agent, so it is only ever rendered as text: React escapes
// `{...}` values. Never use dangerouslySetInnerHTML in this file.
export function FlagItem({ flag }: { flag: Flag }) {
  return (
    <li className={`flag ${flag.severity}`}>
      <div className="what-ran">
        <span className="tool">{flag.tool}</span> <code>{flag.target}</code>
      </div>
      {flag.stated_reason && <p className="reason">{flag.stated_reason}</p>}
      <div className="tags">
        <span className="rule">{flag.rule}</span>
        <span className="severity">{flag.severity}</span>
        {flag.label && <span className="label">{flag.label}</span>}
      </div>
      <ul className="evidence">
        {Object.entries(flag.evidence).map(([key, value]) => (
          <li key={key}>{`${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`}</li>
        ))}
      </ul>
      <div className="where">
        <time dateTime={flag.time}>{new Date(flag.time).toLocaleString()}</time>
        <span className="project">{flag.project}</span>
      </div>
    </li>
  );
}
