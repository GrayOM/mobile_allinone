import { FormEvent, useEffect, useState } from "react";
import { api, post } from "../api";
import type { Device } from "../types";
import { EmptyState, SectionHeading, StatusChip } from "../components/UI";

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [errors, setErrors] = useState<Array<{ adapter: string; error: string }>>([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(() => localStorage.getItem("msw.device") ?? "");
  const [operation, setOperation] = useState<Record<string, unknown> | null>(null);
  const [showIOS, setShowIOS] = useState(false);
  const [iosSaving, setIOSSaving] = useState(false);

  function discover() {
    setLoading(true);
    api<{ devices: Device[]; adapter_errors: Array<{ adapter: string; error: string }> }>("/devices")
      .then((result) => {
        setDevices(result.devices);
        setErrors(result.adapter_errors);
      })
      .finally(() => setLoading(false));
  }

  useEffect(discover, []);

  function choose(device: Device) {
    setSelected(device.id);
    localStorage.setItem("msw.device", device.id);
    localStorage.setItem("msw.deviceAdapter", device.adapter);
  }

  async function inspect(device: Device, action: string) {
    const result = await post<Record<string, unknown>>("/devices/action", {
      adapter: device.adapter,
      device_id: device.id,
      action,
    });
    setOperation(result);
  }

  async function registerIOS(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setIOSSaving(true);
    try {
      await post("/devices/ios/profiles", {
        name: data.get("name"),
        host: data.get("host"),
        ssh_port: Number(data.get("ssh_port")),
        username: data.get("username"),
        frida_endpoint: data.get("frida_endpoint") || null,
        notes: data.get("notes") || "",
      });
      setShowIOS(false);
      discover();
    } finally {
      setIOSSaving(false);
    }
  }

  return (
    <div className="stack stack--lg">
      <SectionHeading
        eyebrow="DEVICE FABRIC"
        title="실단말과 Mock 단말을 같은 방식으로 다룹니다"
        description="ADB, SSH·Frida, Mock Adapter가 공통 기능 상태를 보고합니다."
        action={<div className="button-row"><button className="button button--quiet" onClick={() => setShowIOS(true)}>iOS 단말 등록</button><button className="button button--primary" onClick={discover} disabled={loading}>{loading ? "검색 중…" : "다시 검색"}</button></div>}
      />
      {showIOS && (
        <section className="panel panel--accent">
          <div className="section-heading compact-heading">
            <div><span className="eyebrow">IOS WINDOWS ADAPTER</span><h2>SSH·Frida 연결 프로필</h2><p>비밀번호는 저장하지 않습니다. Windows OpenSSH와 키 기반 인증을 준비하세요.</p></div>
          </div>
          <form className="form-grid" onSubmit={registerIOS}>
            <div className="field"><label htmlFor="ios-name">표시 이름</label><input id="ios-name" name="name" required placeholder="테스트 iPhone" /></div>
            <div className="field"><label htmlFor="ios-host">SSH 호스트</label><input id="ios-host" name="host" required placeholder="192.168.0.25" /></div>
            <div className="field"><label htmlFor="ios-port">SSH 포트</label><input id="ios-port" name="ssh_port" type="number" min="1" max="65535" defaultValue="22" /></div>
            <div className="field"><label htmlFor="ios-user">SSH 사용자</label><input id="ios-user" name="username" defaultValue="root" /></div>
            <div className="field field--wide"><label htmlFor="ios-frida">Frida endpoint</label><input id="ios-frida" name="frida_endpoint" placeholder="예: 192.168.0.25:27042" /></div>
            <div className="field field--wide"><label htmlFor="ios-notes">메모</label><textarea id="ios-notes" name="notes" rows={2} placeholder="탈옥 상태와 승인 범위를 기록하세요." /></div>
            <div className="form-actions field--wide"><button type="button" className="button button--quiet" onClick={() => setShowIOS(false)}>취소</button><button className="button button--primary" disabled={iosSaving}>{iosSaving ? "저장 중…" : "프로필 저장·연결 확인"}</button></div>
          </form>
        </section>
      )}
      <div className="device-grid">
        {devices.map((device) => (
          <article className={`device-card ${selected === device.id ? "device-card--selected" : ""}`} key={`${device.adapter}-${device.id}`}>
            <button className="device-card__select" onClick={() => choose(device)} aria-label={`${device.model} 선택`} />
            <div className="device-card__visual" aria-hidden="true">
              <div>
                <span>{device.platform.includes("ios") ? "iOS" : "AND"}</span>
                <i />
              </div>
            </div>
            <div className="device-card__body">
              <div className="device-card__head">
                <div>
                  <span className="eyebrow">{device.adapter}</span>
                  <h3>{device.model}</h3>
                </div>
                <StatusChip value={device.availability} />
              </div>
              <code>{device.id}</code>
              <dl className="spec-list">
                <div><dt>OS</dt><dd>{device.os_version}</dd></div>
                <div><dt>CPU</dt><dd>{device.architecture}</dd></div>
                <div><dt>연결</dt><dd>{device.connection}</dd></div>
                <div><dt>권한</dt><dd>{device.privileged === null ? "미확인" : device.privileged ? "특권" : "일반"}</dd></div>
              </dl>
              <div className="device-status-row">
                <StatusChip value={device.frida_status} label={`Frida · ${device.frida_status}`} />
                <StatusChip value={device.proxy_status} label={`Proxy · ${device.proxy_status}`} />
              </div>
              <div className="button-row">
                <button className="button button--small" onClick={() => void inspect(device, "list_packages")}>앱 목록</button>
                <button className="button button--small" onClick={() => void inspect(device, "frida_status")}>Frida 확인</button>
              </div>
            </div>
          </article>
        ))}
      </div>
      {!devices.length && !loading && (
        <EmptyState title="검색된 단말이 없습니다" description="Mock 단말도 보이지 않으면 로컬 API 연결 상태를 확인하세요." />
      )}
      {errors.map((item) => <div className="inline-alert" key={item.adapter}>{item.adapter}: {item.error}</div>)}
      {operation && (
        <section className="panel">
          <div className="panel-label">최근 Adapter 결과</div>
          <pre className="code-view">{JSON.stringify(operation, null, 2)}</pre>
        </section>
      )}
    </div>
  );
}
