import streamlit as st
import requests
import json
from datetime import datetime
import hashlib
import pandas as pd
import numpy as np

# API endpoint
API_URL = "http://localhost:8000"

def hash_transaction(transaction_data):
    """İşlem verilerini hash'ler"""
    transaction_str = json.dumps(transaction_data, sort_keys=True)
    return hashlib.sha256(transaction_str.encode()).hexdigest()

def login(username, password):
    """Kullanıcı girişi yapar ve token döndürür"""
    try:
        response = requests.post(
            f"{API_URL}/token",
            data={"username": username, "password": password}
        )
        if response.status_code == 200:
            return response.json()["access_token"]
        return None
    except:
        return None

def get_user_info(token):
    """Kullanıcı bilgilerini getirir"""
    try:
        response = requests.get(
            f"{API_URL}/users/me",
            headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def main():
    st.title("Aidat ve Bağış Takip Sistemi")
    
    # Session state yönetimi
    if "token" not in st.session_state:
        st.session_state.token = None
    if "user" not in st.session_state:
        st.session_state.user = None
    
    # Giriş yapılmamışsa giriş/kayıt menüsünü göster
    if not st.session_state.token:
        menu = st.sidebar.selectbox(
            "Menü",
            ["Giriş", "Kayıt Ol"]
        )
        
        if menu == "Giriş":
            st.header("Giriş Yap")
            username = st.text_input("Kullanıcı Adı")
            password = st.text_input("Şifre", type="password")
            
            if st.button("Giriş Yap"):
                token = login(username, password)
                if token:
                    st.session_state.token = token
                    st.session_state.user = get_user_info(token)
                    st.success("Giriş başarılı!")
                    st.rerun()
                else:
                    st.error("Giriş başarısız!")
                
        elif menu == "Kayıt Ol":
            st.header("Yeni Kullanıcı Kaydı")
            email = st.text_input("E-posta")
            username = st.text_input("Kullanıcı Adı")
            password = st.text_input("Şifre", type="password")
            
            if st.button("Kayıt Ol"):
                try:
                    response = requests.post(
                        f"{API_URL}/users/",
                        json={
                            "email": email,
                            "username": username,
                            "password": password
                        }
                    )
                    if response.status_code == 200:
                        st.success("Kayıt başarılı! Giriş yapabilirsiniz.")
                    else:
                        st.error("Kayıt başarısız!")
                except:
                    st.error("Bir hata oluştu!")
    
    # Giriş yapılmışsa ana menüyü göster
    else:
        # Çıkış yap butonu
        if st.sidebar.button("Çıkış Yap"):
            st.session_state.token = None
            st.session_state.user = None
            st.rerun()
        
        # Admin veya normal kullanıcı menüsü
        if st.session_state.user and st.session_state.user.get("is_admin"):
            menu = st.sidebar.selectbox(
                "Admin Menüsü",
                ["Dashboard", "Kullanıcı Yönetimi", "Aidat Yönetimi", "İstatistikler"]
            )
            
            if menu == "Dashboard":
                st.header("Admin Dashboard")
                st.write(f"Hoş geldiniz, {st.session_state.user['username']}!")
                
            elif menu == "Kullanıcı Yönetimi":
                st.header("Kullanıcı Yönetimi")
                try:
                    response = requests.get(
                        f"{API_URL}/users/",
                        headers={"Authorization": f"Bearer {st.session_state.token}"}
                    )
                    if response.status_code == 200:
                        users = response.json()
                        for user in users:
                            col1, col2 = st.columns([3, 1])
                            with col1:
                                st.write(f"**{user['username']}** ({user['email']})")
                            with col2:
                                if not user['is_admin']:
                                    if st.button("Admin Yap", key=f"admin_{user['id']}"):
                                        try:
                                            response = requests.post(
                                                f"{API_URL}/admin/users/{user['id']}/make-admin",
                                                headers={"Authorization": f"Bearer {st.session_state.token}"}
                                            )
                                            if response.status_code == 200:
                                                st.success("Kullanıcı admin yapıldı!")
                                                st.rerun()
                                                return
                                            else:
                                                st.error(f"İşlem başarısız! Hata: {response.text}")
                                        except Exception as e:
                                            st.error(f"İşlem başarısız! Hata: {str(e)}")
                    else:
                        st.error(f"Kullanıcılar yüklenemedi! Hata: {response.status_code} - {response.text}")
                except Exception as e:
                    st.error(f"Kullanıcılar yüklenemedi! Hata: {str(e)}")
                
            elif menu == "Aidat Yönetimi":
                st.header("Aidat Yönetimi")
                # Smart Contract oluşturma bölümü
                st.subheader("Smart Contract Oluştur")
                with st.form("create_contract_form"):
                    title = st.text_input("Başlık (örn: Ocak 2025 Aidatı)")
                    description = st.text_area("Açıklama")
                    
                    submitted = st.form_submit_button("Smart Contract Oluştur")
                    if submitted:
                        try:
                            response = requests.post(
                                f"{API_URL}/smart-contracts/",
                                headers={"Authorization": f"Bearer {st.session_state['token']}"},
                                json={
                                    "title": title,
                                    "description": description
                                }
                            )
                            if response.status_code == 200:
                                st.success("Smart Contract başarıyla oluşturuldu!")
                            else:
                                st.error(f"Hata: {response.json().get('detail', 'Bilinmeyen hata')}")
                        except Exception as e:
                            st.error(f"Bir hata oluştu: {str(e)}")
                if st.session_state.get("last_contract_id"):
                    st.info(f"Oluşturulan Smart Contract ID: {st.session_state['last_contract_id']}")
                    st.code(st.session_state['last_contract_id'])
                    st.write("Bu ID'yi kopyalayıp aşağıdaki Sözleşme ID alanına yapıştırabilirsiniz.")
                # Smart Contract listeleme bölümü
                st.subheader("Kayıtlı Smart Contract'lar")
                try:
                    response = requests.get(
                        f"{API_URL}/smart-contracts/",
                        headers={"Authorization": f"Bearer {st.session_state.token}"}
                    )
                    if response.status_code == 200:
                        contracts = response.json()
                        if contracts:
                            df = pd.DataFrame(contracts)
                            df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                            df = df[['contract_id', 'title', 'description', 'created_at']]
                            df.columns = ['Contract ID', 'Başlık', 'Açıklama', 'Oluşturulma Tarihi']
                            st.dataframe(df, use_container_width=True)
                            for contract in contracts:
                                contract_id = contract['contract_id']
                                st.write(f"**ID:** {contract_id}  ")
                                st.write(f"Başlık: {contract['title']}")
                                st.write(f"Açıklama: {contract['description']}")
                                st.write(f"Oluşturulma Tarihi: {pd.to_datetime(contract['created_at']).strftime('%Y-%m-%d %H:%M')}")
                                
                                # Kopyalanabilir ID alanı
                                st.code(contract_id, language="text")
                                st.caption("ID'yi kopyalamak için yukarıdaki kodu seçip Ctrl+C yapın")
                                
                                if st.button("🗑️ Sil", key=f"delete_{contract_id}"):
                                    try:
                                        del_response = requests.delete(
                                            f"{API_URL}/smart-contracts/{contract_id}",
                                            headers={"Authorization": f"Bearer {st.session_state.token}"}
                                        )
                                        if del_response.status_code == 200:
                                            st.success("Smart contract silindi!")
                                            st.experimental_rerun()
                                        else:
                                            st.error(f"Silme hatası: {del_response.json().get('detail', 'Bilinmeyen hata')}")
                                    except Exception as e:
                                        st.error(f"Silme sırasında hata: {str(e)}")
                                st.markdown('---')
                        else:
                            st.info("Henüz smart contract yok.")
                    else:
                        st.error(f"Hata: {response.json().get('detail', 'Bilinmeyen hata')}")
                except Exception as e:
                    st.error(f"Bir hata oluştu: {str(e)}")
                st.subheader("Yeni Aidat Oluştur")
                with st.form("new_due"):
                    amount = st.number_input("Tutar", min_value=0.0)
                    description = st.text_input("Açıklama")
                    due_date = st.date_input("Son Ödeme Tarihi")
                    contract_id = st.text_input("Sözleşme ID (zorunlu)", value=st.session_state.get("last_contract_id", ""))
                    if st.form_submit_button("Oluştur"):
                        if not contract_id:
                            st.error("Sözleşme ID zorunludur!")
                        else:
                            try:
                                # due_date'i ISO formatına saat ekleyerek gönder
                                due_date_str = datetime.combine(due_date, datetime.min.time()).isoformat()
                                response = requests.post(
                                    f"{API_URL}/dues/",
                                    headers={"Authorization": f"Bearer {st.session_state.token}"},
                                    json={
                                        "amount": amount,
                                        "description": description,
                                        "due_date": due_date_str,
                                        "contract_id": contract_id,
                                        "owner_id": st.session_state.user["id"]
                                    }
                                )
                                if response.status_code == 200:
                                    st.success("Aidat başarıyla oluşturuldu!")
                                else:
                                    st.error(f"Aidat oluşturulamadı! Hata: {response.text}")
                            except Exception as e:
                                st.error(f"Bir hata oluştu: {str(e)}")
                
            elif menu == "İstatistikler":
                st.header("İstatistikler ve Raporlar")
                
                # Tüm kullanıcıları çek
                users_response = requests.get(
                    f"{API_URL}/users/",
                    headers={"Authorization": f"Bearer {st.session_state.token}"}
                )
                
                if users_response.status_code == 200:
                    users = users_response.json()
                    normal_users = [user for user in users if not user.get('is_admin', False)]
                    
                    # Genel İstatistikler
                    st.subheader("Genel İstatistikler")
                    col1, col2, col3 = st.columns(3)
                    
                    # Tüm aidatları çek
                    dues_response = requests.get(
                        f"{API_URL}/dues/",
                        headers={"Authorization": f"Bearer {st.session_state.token}"}
                    )
                    
                    if dues_response.status_code != 200:
                        st.error("Aidatlar yüklenemedi!")
                        return
                        
                    dues = dues_response.json()
                    
                    total_dues = 0
                    total_amount = 0
                    total_tam_odeme = 0
                    total_kismi_odeme = 0
                    total_users = len(normal_users)
                    
                    for due in dues:
                        total_dues += 1
                        total_amount += due['amount']
                        
                        # Bu aidata ait tüm ödemeleri al
                        tx_response = requests.get(
                            f"{API_URL}/transactions/?due_id={due['id']}",
                            headers={"Authorization": f"Bearer {st.session_state.token}"}
                        )
                        
                        if tx_response.status_code == 200:
                            transactions = tx_response.json()
                            
                            # Her kullanıcı için ödeme kontrolü
                            for user in normal_users:
                                user_paid = sum(
                                    tx.get('amount', 0) 
                                    for tx in transactions 
                                    if tx.get('user_id') == user['id']
                                )
                                
                                if user_paid >= due['amount']:
                                    total_tam_odeme += 1
                                elif user_paid > 0:
                                    total_kismi_odeme += 1
                    
                    with col1:
                        st.metric("Toplam Kullanıcı", total_users)
                    with col2:
                        st.metric("Toplam Aidat Tutarı", f"{total_amount:.2f} TL")
                    with col3:
                        tam_odeme_orani = (total_tam_odeme / (total_users * total_dues) * 100) if total_users * total_dues > 0 else 0
                        st.metric("Tam Ödeme Oranı", f"%{tam_odeme_orani:.1f}")
                    
                    # Detaylı ödeme istatistikleri
                    st.write("---")
                    st.write("Detaylı Ödeme İstatistikleri:")
                    st.write(f"Toplam Tam Ödeme: {total_tam_odeme}")
                    st.write(f"Toplam Kısmi Ödeme: {total_kismi_odeme}")
                    st.write(f"Toplam Ödeme Yapılmayan: {(total_users * total_dues) - total_tam_odeme - total_kismi_odeme}")
                    
                    # Aylık İstatistikler
                    st.subheader("Aylık İstatistikler")
                    # Her aidat için ödeme istatistiklerini hesapla
                    for due in dues:
                        # Bu aidata ait tüm ödemeleri al
                        tx_response = requests.get(
                            f"{API_URL}/transactions/?due_id={due['id']}",
                            headers={"Authorization": f"Bearer {st.session_state.token}"}
                        )
                        
                        if tx_response.status_code == 200:
                            transactions = tx_response.json()
                            
                            # Her kullanıcı için ayrı ayrı ödeme kontrolü
                            tam_odeme_yapan_kisi = 0
                            kismi_odeme_yapan_kisi = 0
                            toplam_kisi = 0
                            
                            for user in users:
                                if user.get('is_admin', False):
                                    continue
                                    
                                toplam_kisi += 1
                                # Bu kullanıcının bu aidata yaptığı ödemeleri topla
                                user_paid = sum(
                                    tx.get('amount', 0) 
                                    for tx in transactions 
                                    if tx.get('user_id') == user['id']
                                )
                                
                                # Ödeme durumunu kontrol et
                                if user_paid >= due['amount']:
                                    tam_odeme_yapan_kisi += 1
                                elif user_paid > 0:
                                    kismi_odeme_yapan_kisi += 1
                            
                            # Ödeme oranlarını hesapla
                            tam_odeme_orani = (tam_odeme_yapan_kisi / toplam_kisi * 100) if toplam_kisi > 0 else 0
                            kismi_odeme_orani = (kismi_odeme_yapan_kisi / toplam_kisi * 100) if toplam_kisi > 0 else 0
                            
                            # İstatistikleri göster
                            st.write(f"Aidat: {due['description']}")
                            st.write(f"Toplam Kişi: {toplam_kisi}")
                            st.write(f"Tam Ödeme Yapan: {tam_odeme_yapan_kisi} (%{tam_odeme_orani:.1f})")
                            st.write(f"Kısmi Ödeme Yapan: {kismi_odeme_yapan_kisi} (%{kismi_odeme_orani:.1f})")
                            st.write(f"Hiç Ödeme Yapmayan: {toplam_kisi - tam_odeme_yapan_kisi - kismi_odeme_yapan_kisi}")
                            st.markdown('---')
                    
                    # Kullanıcı Bazlı Detaylı Liste
                    st.subheader("Kullanıcı Bazlı Aidat Listesi")
                    for user in normal_users:
                        with st.expander(f"{user['username']} ({user['email']})"):
                            dues_response = requests.get(
                                f"{API_URL}/dues/?owner_id={user['id']}",
                                headers={"Authorization": f"Bearer {st.session_state.token}"}
                            )
                            if dues_response.status_code == 200:
                                dues = dues_response.json()
                                if dues:
                                    for due in dues:
                                        st.write(f"Açıklama: {due['description']}")
                                        st.write(f"Tutar: {due['amount']} TL")
                                        st.write(f"Son Tarih: {due['due_date']}")
                                        
                                        # Kullanıcının bu aidata yaptığı ödemeleri al
                                        tx_response = requests.get(
                                            f"{API_URL}/transactions/?user_id={user['id']}&due_id={due['id']}",
                                            headers={"Authorization": f"Bearer {st.session_state.token}"}
                                        )
                                        
                                        total_paid = 0.0
                                        if tx_response.status_code == 200:
                                            transactions = tx_response.json()
                                            total_paid = sum(tx.get('amount', 0) for tx in transactions)
                                        
                                        kalan = round(due['amount'] - total_paid, 2)
                                        kalan = max(kalan, 0)
                                        
                                        # Ödeme durumunu belirle
                                        if kalan == 0:
                                            odeme_durumu = "✅ Ödendi"
                                        elif kalan < due['amount']:
                                            odeme_durumu = f"🟡 Kısmi Ödeme (%{(total_paid/due['amount']*100):.1f})"
                                        else:
                                            odeme_durumu = "❌ Ödenmedi"
                                        
                                        st.write(f"Durum: {odeme_durumu}")
                                        st.write(f"Ödenen: {total_paid} TL")
                                        st.write(f"Kalan: {kalan} TL")
                                        st.markdown('---')
                                else:
                                    st.info("Bu kullanıcıya ait aidat yok.")
                            else:
                                st.error("Aidatlar yüklenemedi!")
                else:
                    st.error("Kullanıcılar yüklenemedi!")
        
        else:
            menu = st.sidebar.selectbox(
                "Menü",
                ["Aidat İşlemleri", "İşlem Geçmişi"]
            )
            
            if menu == "Aidat İşlemleri":
                st.header("Aidat İşlemleri")
                
                # Tüm aidatları getir (owner_id filtresi olmadan)
                dues_response = requests.get(
                    f"{API_URL}/dues/",
                    headers={"Authorization": f"Bearer {st.session_state.token}"}
                )
                if dues_response.status_code == 200:
                    dues = dues_response.json()
                    if dues:
                        for due in dues:
                            st.subheader(f"Açıklama: {due['description']}")
                            st.write(f"Tutar: {due['amount']} TL")
                            st.write(f"Son Tarih: {due['due_date']}")
                            # Kullanıcının ödemelerini al
                            tx_response = requests.get(
                                f"{API_URL}/transactions/?user_id={st.session_state.user['id']}&due_id={due['id']}",
                                headers={"Authorization": f"Bearer {st.session_state.token}"}
                            )
                            
                            total_paid = 0.0
                            if tx_response.status_code == 200:
                                transactions = tx_response.json()
                                # Sadece bu kullanıcının ödemelerini topla
                                total_paid = sum(tx.get('amount', 0) for tx in transactions if tx.get('user_id') == st.session_state.user['id'])
                            
                            kalan = round(due['amount'] - total_paid, 2)
                            kalan = max(kalan, 0)  # Negatif değer olmamasını sağla
                            
                            # Ödeme durumunu belirle
                            if kalan == 0:
                                odeme_durumu = "Ödendi"
                                odeme_renk = "green"
                            elif kalan < due['amount']:
                                odeme_durumu = "Kısmi Ödeme"
                                odeme_renk = "orange"
                            else:
                                odeme_durumu = "Ödenmedi"
                                odeme_renk = "red"
                            
                            st.write(f"Ödeme Durumu: {odeme_durumu}")
                            st.write(f"Kalan Tutar: {kalan} TL")
                            st.write(f"Ödeme Tutarı: {total_paid} TL")
                            
                            # Eğer kalan tutar varsa ödeme formunu göster
                            if kalan > 0:
                                pay_amount = st.number_input(
                                    f"Ödeme Tutarı (max: {kalan} TL)",
                                    min_value=0.01,
                                    max_value=kalan,
                                    step=0.01,
                                    key=f"pay_amount_{due['id']}"
                                )
                                if st.button(f"Öde", key=f"pay_{due['id']}"):
                                    try:
                                        pay_response = requests.post(
                                            f"{API_URL}/dues/{due['id']}/pay",
                                            headers={"Authorization": f"Bearer {st.session_state.token}"},
                                            json={"amount": pay_amount, "description": due['description']}
                                        )
                                        if pay_response.status_code == 200:
                                            st.success("Ödeme başarıyla gerçekleştirildi!")
                                            st.experimental_rerun()
                                        else:
                                            st.error(f"Ödeme başarısız! Hata: {pay_response.text}")
                                    except Exception as e:
                                        st.error(f"Ödeme sırasında bir hata oluştu: {str(e)}")
                            
                            st.markdown('---')
                    else:
                        st.info("Ödemeniz gereken aidat bulunmamaktadır.")
                else:
                    st.error("Aidatlar yüklenemedi!")
                
            elif menu == "İşlem Geçmişi":
                st.header("İşlem Geçmişi")
                # Kullanıcının yaptığı işlemleri getir
                tx_response = requests.get(
                    f"{API_URL}/transactions/?user_id={st.session_state.user['id']}",
                    headers={"Authorization": f"Bearer {st.session_state.token}"}
                )
                if tx_response.status_code == 200:
                    transactions = tx_response.json()
                    if transactions:
                        for tx in transactions:
                            st.write(f"Tarih: {tx['created_at']}")
                            st.write(f"İşlem Türü: {tx['transaction_type']}")
                            st.write(f"Tutar: {tx['amount']} TL")
                            st.write(f"Açıklama: {tx['description']}")
                            st.markdown('---')
                    else:
                        st.info("Henüz işlem geçmişiniz yok.")
                else:
                    st.error("İşlem geçmişi yüklenemedi!")

def smart_contract_page():
    st.title("Smart Contract İşlemleri")
    
    # Token kontrolü
    if 'token' not in st.session_state:
        st.error("Lütfen önce giriş yapın!")
        return
    
    # Admin kontrolü
    if not st.session_state.get('is_admin', False):
        st.error("Bu sayfaya erişim için admin yetkisi gerekiyor!")
        return
    
    # Smart Contract Oluşturma
    st.subheader("Yeni Smart Contract Oluştur")
    with st.form("create_contract_form"):
        title = st.text_input("Başlık (örn: Ocak 2025 Aidatı)")
        description = st.text_area("Açıklama")
        
        submitted = st.form_submit_button("Smart Contract Oluştur")
        if submitted:
            try:
                response = requests.post(
                    f"{API_URL}/smart-contracts/",
                    headers={"Authorization": f"Bearer {st.session_state['token']}"},
                    json={
                        "title": title,
                        "description": description
                    }
                )
                if response.status_code == 200:
                    st.success("Smart Contract başarıyla oluşturuldu!")
                else:
                    st.error(f"Hata: {response.json().get('detail', 'Bilinmeyen hata')}")
            except Exception as e:
                st.error(f"Bir hata oluştu: {str(e)}")
    
    # Mevcut Smart Contract'ları Listele
    st.subheader("Aktif Smart Contract'lar")
    try:
        response = requests.get(
            f"{API_URL}/smart-contracts/",
            headers={"Authorization": f"Bearer {st.session_state['token']}"}
        )
        if response.status_code == 200:
            contracts = response.json()
            if contracts:
                # DataFrame oluştur
                df = pd.DataFrame(contracts)
                df['created_at'] = pd.to_datetime(df['created_at']).dt.strftime('%Y-%m-%d %H:%M')
                df = df[['contract_id', 'title', 'description', 'created_at']]
                df.columns = ['Contract ID', 'Başlık', 'Açıklama', 'Oluşturulma Tarihi']
                st.dataframe(df)
            else:
                st.info("Henüz hiç smart contract oluşturulmamış.")
        else:
            st.error(f"Hata: {response.json().get('detail', 'Bilinmeyen hata')}")
    except Exception as e:
        st.error(f"Bir hata oluştu: {str(e)}")

def user_smart_contract_page():
    st.title("Smart Contract Ödemeleri")
    
    # Token kontrolü
    if 'token' not in st.session_state:
        st.error("Lütfen önce giriş yapın!")
        return
    
    # Aktif Smart Contract'ları Listele
    st.subheader("Ödeme Yapılabilecek Smart Contract'lar")
    try:
        response = requests.get(
            f"{API_URL}/smart-contracts/",
            headers={"Authorization": f"Bearer {st.session_state['token']}"}
        )
        if response.status_code == 200:
            contracts = response.json()
            if contracts:
                for contract in contracts:
                    with st.expander(f"{contract['title']} - {contract['amount']} TL"):
                        st.write(f"**Açıklama:** {contract['description']}")
                        st.write(f"**Contract ID:** {contract['contract_id']}")
                        if st.button(f"{contract['title']} için Ödeme Yap", key=contract['contract_id']):
                            try:
                                payment_response = requests.post(
                                    f"{API_URL}/smart-contracts/{contract['contract_id']}/pay",
                                    headers={"Authorization": f"Bearer {st.session_state['token']}"}
                                )
                                if payment_response.status_code == 200:
                                    st.success("Ödeme başarıyla gerçekleştirildi!")
                                else:
                                    st.error(f"Ödeme hatası: {payment_response.json().get('detail', 'Bilinmeyen hata')}")
                            except Exception as e:
                                st.error(f"Ödeme sırasında bir hata oluştu: {str(e)}")
            else:
                st.info("Şu anda ödeme yapılabilecek aktif smart contract bulunmuyor.")
        else:
            st.error(f"Hata: {response.json().get('detail', 'Bilinmeyen hata')}")
    except Exception as e:
        st.error(f"Bir hata oluştu: {str(e)}")

# Ana menüye smart contract sayfalarını ekle
# if st.session_state.get('is_admin', False):
#     if st.sidebar.button("Smart Contract Yönetimi"):
#         smart_contract_page()
# else:
#     if st.sidebar.button("Smart Contract Ödemeleri"):
#         user_smart_contract_page()

if __name__ == "__main__":
    main() 